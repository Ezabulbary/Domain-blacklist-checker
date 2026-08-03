import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadEnv } from './lib/env.js';

loadEnv(); // read .env before anything reads process.env

import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { checkDomain } from './lib/check.js';
import { checkMany, resultsToCsv } from './lib/bulk.js';
import { analyzeDomain } from './lib/analyze.js';
import { checkAuth } from './lib/auth.js';
import { createApiKey, validateApiKey } from './lib/apikeys.js';
import { getCalibration, isTrusted, summarize } from './lib/calibrate.js';
import { removalGuide, KIND_LABEL } from './lib/removal.js';
import { readiness, stillListed } from './lib/delist.js';
import { buildResolver } from './lib/resolve.js';
import { ALL_ZONES, CATEGORIES } from './lib/zones.js';
import { dbEnabled } from './db/pool.js';
import { db } from './db/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// One shared resolver for the process (see resolve.js for DBC_RESOLVERS).
const resolver = buildResolver();
// A more patient resolver for auth / full-record lookups: big TXT answers
// (SPF on large senders) are slow, and one retry rescues a flaky query.
const authResolver = buildResolver(null, { timeout: 5000, tries: 2 });

// Tiny in-memory cache so repeat lookups don't re-hammer the DNSBLs. In
// production this becomes Redis with a 15-30 min TTL (plan §5.3). Caching is
// mandatory, not optional, to stay inside free query limits.
const CACHE_TTL_MS = Number(process.env.DBC_CACHE_TTL_MS ?? 15 * 60 * 1000);
const CACHE_MAX = Number(process.env.DBC_CACHE_MAX ?? 5000);
const cache = new Map(); // domain -> { at, value }

function cached(key) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
  cache.delete(key);
  return null;
}

// Bounded insert: cap the cache so a flood of unique domains can't exhaust
// memory. Map preserves insertion order, so deleting the first key evicts the
// oldest (FIFO). In production this Map is replaced by Redis.
function cacheSet(key, value) {
  cache.set(key, { at: Date.now(), value });
  while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
}

// Very small fixed-window rate limiter per IP (plan §5.5). Protect our own IP
// from being blocked by the DNSBLs due to a caller's abuse.
const RATE_MAX = Number(process.env.DBC_RATE_MAX ?? 30);
const RATE_WINDOW_MS = Number(process.env.DBC_RATE_WINDOW_MS ?? 60 * 1000);
const hits = new Map(); // ip -> { count, resetAt }

const RATE_MAX_KEYED = Number(process.env.DBC_RATE_MAX_KEYED ?? RATE_MAX * 5);
const REQUIRE_KEY = process.env.DBC_REQUIRE_KEY === 'true';

let lastSweep = 0;
// `cost` lets an expensive request (a bulk check fanning out thousands of DNS
// queries) consume more of the budget than a single lookup, so bulk can't be
// used to amplify load. `id` is the bucket (IP, or the API key) and `max` its
// budget. Authenticated callers get a higher one.
function rateLimited(id, cost = 1, max = RATE_MAX) {
  const now = Date.now();
  // Periodically drop expired windows so the map can't grow without bound from
  // a stream of distinct client IPs (memory-exhaustion DoS).
  if (now - lastSweep > RATE_WINDOW_MS) {
    for (const [k, v] of hits) if (now > v.resetAt) hits.delete(k);
    lastSweep = now;
  }
  const rec = hits.get(id);
  if (!rec || now > rec.resetAt) {
    hits.set(id, { count: cost, resetAt: now + RATE_WINDOW_MS });
    return cost > max;
  }
  rec.count += cost;
  return rec.count > max;
}

// Authenticate a request from its optional X-API-Key. Returns false and sends a
// 401 when a key is invalid, or when DBC_REQUIRE_KEY is on and none was given.
async function authOk(req, reply) {
  const key = (req.headers['x-api-key'] || req.query.api_key || '').toString().trim();
  if (!key) {
    if (REQUIRE_KEY) {
      reply.code(401).send({ ok: false, error: 'API key required. Send it as the X-API-Key header' });
      return false;
    }
    return true;
  }
  const v = await validateApiKey(key);
  if (!v) {
    reply.code(401).send({ ok: false, error: 'invalid API key' });
    return false;
  }
  req.apiKey = key;
  req.apiPlan = v.plan;
  return true;
}

// Rate-limit a request, bucketed and budgeted by whether it's authenticated.
function limited(req, cost = 1) {
  return req.apiKey
    ? rateLimited('k:' + req.apiKey, cost, RATE_MAX_KEYED)
    : rateLimited(req.ip, cost, RATE_MAX);
}

// Persist a successful check when a database is configured. Never let a DB
// hiccup break the response. Persistence is best-effort here.
async function persist(result) {
  if (!dbEnabled() || !result.ok) return;
  try {
    await db.checks.saveCheck(result);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[db] saveCheck failed:', e.message);
  }
}

// Cache-aware single check, reused by both the single and bulk routes.
async function checkCached(domain, opts) {
  const key = domain.trim().toLowerCase();
  const hit = cached(key);
  if (hit) return { ...hit, cached: true };
  const result = await checkDomain(domain, opts);
  if (result.ok) {
    cacheSet(key, result);
    await persist(result);
  }
  return { ...result, cached: false };
}

// Split a pasted blob / CSV / uploaded file into candidate domains. We accept
// newline-, comma-, whitespace- or semicolon-separated input and, for CSV rows,
// keep only the first field so "example.com,extra,notes" still works.
function parseDomainList(text) {
  return String(text)
    .split(/[\r\n]+/)
    .map((line) => line.split(/[,;\t]/)[0])
    .flatMap((cell) => cell.split(/\s+/))
    .map((s) => s.trim())
    .filter(Boolean);
}

const BULK_MAX = Number(process.env.DBC_BULK_MAX ?? 500);
const BULK_CONCURRENCY = Number(process.env.DBC_BULK_CONCURRENCY ?? 5);

export function buildServer() {
  const app = Fastify({
    logger: process.env.NODE_ENV !== 'test',
    bodyLimit: Number(process.env.DBC_BODY_LIMIT ?? 2 * 1024 * 1024), // 2 MB
    // Only trust X-Forwarded-* when explicitly deployed behind a known proxy,
    // so req.ip (used for rate limiting) reflects the real client there and
    // can't be spoofed when running directly.
    trustProxy: process.env.DBC_TRUST_PROXY === 'true',
  });

  // Baseline security headers on every response. The CSP allows inline
  // script/style because the UI is a single self-contained index.html; it still
  // blocks external script injection, framing and MIME sniffing.
  app.addHook('onSend', async (_req, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
      + "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    return payload;
  });

  // Accept raw text / CSV bodies (paste a list or upload a .csv/.txt).
  const rawParser = (_req, body, done) => done(null, body);
  app.addContentTypeParser('text/plain', { parseAs: 'string' }, rawParser);
  app.addContentTypeParser('text/csv', { parseAs: 'string' }, rawParser);

  app.register(fastifyStatic, {
    root: join(__dirname, '..', 'public'),
    prefix: '/',
  });

  app.get('/api/health', async () => ({ status: 'ok', zones: ALL_ZONES.length, db: dbEnabled() }));

  app.get('/api/zones', async () => ({
    count: ALL_ZONES.length,
    categories: CATEGORIES,
    zones: ALL_ZONES.map(({ name, zone, type, category, weight, severity, status, note }) => ({
      name, zone, type, category, weight, severity, status, note,
    })),
  }));

  // Which blocklists can be trusted from THIS server, and why not (see
  // calibrate.js). ?refresh=1 re-runs the probes.
  app.get('/api/calibration', async (req, reply) => {
    // A forced refresh probes every zone (hundreds of DNS queries), so it is
    // charged like a bulk request; a cached read is cheap.
    const force = req.query.refresh === '1';
    if (limited(req, force ? 10 : 1)) {
      return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    }
    const cal = await getCalibration({ resolver, force });
    const byZone = new Map(ALL_ZONES.map((z) => [z.zone, z]));
    const zones = Object.entries(cal.zones).map(([zone, v]) => ({
      zone, name: byZone.get(zone)?.name || zone, trusted: isTrusted(v.verdict), ...v,
    }));
    return {
      ok: true,
      checkedAt: new Date(cal.at).toISOString(),
      resolvers: cal.resolvers,
      total: zones.length,
      trusted: zones.filter((z) => z.trusted).length,
      summary: summarize(cal),
      zones,
    };
  });

  // Step by step removal guidance for one listing.
  app.get('/api/removal', async (req, reply) => {
    const zone = (req.query.zone || '').toString().trim();
    const z = ALL_ZONES.find((x) => x.zone === zone);
    if (!z) return reply.code(404).send({ ok: false, error: 'unknown blocklist' });
    const subject = (req.query.subject || '').toString().trim();
    return {
      ok: true,
      kindLabels: KIND_LABEL,
      guide: removalGuide({ zone: z.zone, name: z.name, type: z.type, delist: z.delist, subject }),
    };
  });

  // Only [a-z0-9.-] hostnames / IPs are ever embedded in a DNS query name, so
  // arbitrary input can't be used to craft odd lookups via the delist routes.
  const SUBJECT_RE = /^[a-z0-9.-]{1,253}$/i;

  // Start an assisted removal: check from DNS whether the sender meets what the
  // list requires, and hand back a prefilled removal URL.
  app.get('/api/delist/start', async (req, reply) => {
    const zone = (req.query.zone || '').toString().trim();
    const subject = (req.query.subject || '').toString().trim().split(',')[0].trim();
    const domain = (req.query.domain || '').toString().trim() || null;
    if (!zone || !subject) return reply.code(400).send({ ok: false, error: 'zone and subject are required' });
    if (!SUBJECT_RE.test(subject) || (domain && !SUBJECT_RE.test(domain))) {
      return reply.code(400).send({ ok: false, error: 'invalid subject or domain' });
    }
    if (!(await authOk(req, reply))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    const z = ALL_ZONES.find((x) => x.zone === zone);
    if (!z) return reply.code(404).send({ ok: false, error: 'unknown blocklist' });
    return { ok: true, name: z.name, ...(await readiness({ zone, subject, domain }, resolver)) };
  });

  // Poll after submitting: has the entry actually gone?
  app.get('/api/delist/status', async (req, reply) => {
    const zone = (req.query.zone || '').toString().trim();
    const subject = (req.query.subject || '').toString().trim();
    if (!zone || !subject) return reply.code(400).send({ ok: false, error: 'zone and subject are required' });
    if (!SUBJECT_RE.test(subject)) return reply.code(400).send({ ok: false, error: 'invalid subject' });
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    const listed = await stillListed(zone, subject, resolver);
    return { ok: true, zone, subject, listed, checkedAt: new Date().toISOString() };
  });

  // Generate a new API key. Optional { email } ties it to a user record.
  app.post('/api/keys', async (req, reply) => {
    if (rateLimited(req.ip, 5)) {
      return reply.code(429).send({ ok: false, error: 'too many key requests, slow down' });
    }
    const email = req.body && typeof req.body === 'object' ? req.body.email : undefined;
    try {
      const r = await createApiKey({ email });
      return {
        ok: true,
        apiKey: r.apiKey,
        plan: r.plan,
        persisted: r.persisted,
        requireKey: REQUIRE_KEY,
        note: r.persisted
          ? 'Send this as the X-API-Key header.'
          : 'Send this as the X-API-Key header. No database is configured, so this key is kept in memory and is lost on restart. Set DATABASE_URL to persist keys.',
      };
    } catch (e) {
      const code = e.message === 'email already registered' ? 409 : 500;
      return reply.code(code).send({ ok: false, error: e.message });
    }
  });

  // Unified deliverability report (blacklists + auth + risk + recommendations).
  app.get('/api/analyze', async (req, reply) => {
    const domain = (req.query.domain || '').toString();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    if (!(await authOk(req, reply))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    // Single-domain view: include the full DNS record sets for the auth tab.
    return analyzeDomain(domain, { resolver, authResolver, withRecords: true });
  });

  // Authentication health only (SPF / DKIM / DMARC / MX / PTR).
  app.get('/api/auth', async (req, reply) => {
    const domain = (req.query.domain || '').toString().trim();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    if (!(await authOk(req, reply))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    // Guard: only [a-z0-9.-] hostnames / selectors are ever embedded in a DNS
    // name, so arbitrary input can't be used to craft odd lookups.
    const HOST_RE = /^[a-z0-9.-]{1,253}$/i;
    const host = domain.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/?#]/)[0].replace(/^www\./i, '');
    if (!HOST_RE.test(host)) return reply.code(400).send({ ok: false, error: 'invalid domain' });
    const sel = req.query.selector ? req.query.selector.toString() : null;
    if (sel && !HOST_RE.test(sel)) return reply.code(400).send({ ok: false, error: 'invalid selector' });
    return {
      ok: true,
      domain: host,
      ...(await checkAuth(host, { resolver: authResolver, selectors: sel ? [sel] : undefined, withRecords: true })),
    };
  });

  // Check history for a domain. Only when a database is configured.
  app.get('/api/history', async (req, reply) => {
    if (!dbEnabled()) return reply.code(501).send({ ok: false, error: 'history requires DATABASE_URL' });
    if (!(await authOk(req, reply))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    const domain = (req.query.domain || '').toString().trim();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    const limit = Math.min(Number(req.query.limit ?? 20), 100);
    const rows = await db.checks.listChecksForDomain(domain, { limit });
    return { ok: true, domain: domain.toLowerCase(), count: rows.length, checks: rows };
  });

  app.get('/api/check', async (req, reply) => {
    const domain = (req.query.domain || '').toString();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    if (!(await authOk(req, reply))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    return checkCached(domain, { resolver });
  });

  // Bulk check. Accepts either:
  //   JSON  { "domains": [...] }  or  { "text": "one per line / CSV" }
  //   text/plain or text/csv body (raw pasted list / uploaded file)
  // Optional ?format=csv returns a downloadable CSV instead of JSON.
  app.post('/api/check/bulk', async (req, reply) => {
    let inputs = [];
    const body = req.body;
    if (typeof body === 'string') {
      inputs = parseDomainList(body);
    } else if (body && Array.isArray(body.domains)) {
      inputs = body.domains;
    } else if (body && typeof body.text === 'string') {
      inputs = parseDomainList(body.text);
    } else {
      return reply.code(400).send({
        ok: false,
        error: 'send { domains: [...] } or { text: "..." } as JSON, or a raw text/csv body',
      });
    }

    if (inputs.length === 0) {
      return reply.code(400).send({ ok: false, error: 'no domains found in request' });
    }
    if (!(await authOk(req, reply))) return;

    // Charge the rate limiter in proportion to the work (each domain fans out
    // to ~100 DNS queries) so bulk can't be used to amplify load. The cost is
    // strictly per-domain with no per-request constant, so a large list sent as
    // several smaller batches costs exactly what one big batch costs. The UI
    // sends batches to keep progress visible and survive proxy timeouts, and it
    // must not be penalized for that.
    const cost = Math.max(1, Math.ceil(Math.min(inputs.length, BULK_MAX) / 25));
    if (limited(req, cost)) {
      return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    }

    // ?auth=1 also pulls SPF, DKIM, DMARC, MX and PTR for every domain. That
    // path cannot use the blocklist-only cache, so it runs the full audit.
    const withAuth = req.query.auth === '1' || (req.body && req.body.auth === true);
    const { results, summary, skipped } = await checkMany(inputs, {
      resolver,
      withAuth,
      concurrency: BULK_CONCURRENCY,
      max: BULK_MAX,
      checkFn: withAuth ? undefined : checkCached,
    });

    if ((req.query.format || '').toString().toLowerCase() === 'csv') {
      reply
        .header('content-type', 'text/csv; charset=utf-8')
        .header('content-disposition', 'attachment; filename="blacklist-report.csv"');
      return resultsToCsv(results);
    }

    return { ok: true, summary, skipped, results };
  });

  return app;
}

// Start only when run directly (not when imported by tests).
const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const app = buildServer();
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? '0.0.0.0';
  app.listen({ port, host }).catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
}
