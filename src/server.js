import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { checkDomain } from './lib/check.js';
import { checkMany, resultsToCsv } from './lib/bulk.js';
import { analyzeDomain } from './lib/analyze.js';
import { checkAuth } from './lib/auth.js';
import { buildResolver } from './lib/resolve.js';
import { ALL_ZONES, CATEGORIES } from './lib/zones.js';
import { dbEnabled } from './db/pool.js';
import { db } from './db/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// One shared resolver for the process (see resolve.js for DBC_RESOLVERS).
const resolver = buildResolver();

// Tiny in-memory cache so repeat lookups don't re-hammer the DNSBLs. In
// production this becomes Redis with a 15-30 min TTL (plan §5.3) — caching is
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

// Very small fixed-window rate limiter per IP (plan §5.5) — protect our own IP
// from being blocked by the DNSBLs due to a caller's abuse.
const RATE_MAX = Number(process.env.DBC_RATE_MAX ?? 30);
const RATE_WINDOW_MS = Number(process.env.DBC_RATE_WINDOW_MS ?? 60 * 1000);
const hits = new Map(); // ip -> { count, resetAt }

let lastSweep = 0;
// `cost` lets an expensive request (a bulk check fanning out thousands of DNS
// queries) consume more of the per-IP budget than a single lookup, so bulk
// can't be used to amplify load or abuse the upstream DNSBLs.
function rateLimited(ip, cost = 1) {
  const now = Date.now();
  // Periodically drop expired windows so the map can't grow without bound from
  // a stream of distinct client IPs (memory-exhaustion DoS).
  if (now - lastSweep > RATE_WINDOW_MS) {
    for (const [k, v] of hits) if (now > v.resetAt) hits.delete(k);
    lastSweep = now;
  }
  const rec = hits.get(ip);
  if (!rec || now > rec.resetAt) {
    hits.set(ip, { count: cost, resetAt: now + RATE_WINDOW_MS });
    return cost > RATE_MAX;
  }
  rec.count += cost;
  return rec.count > RATE_MAX;
}

// Persist a successful check when a database is configured. Never let a DB
// hiccup break the response — persistence is best-effort here.
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

  // Unified deliverability report (blacklists + auth + risk + recommendations).
  app.get('/api/analyze', async (req, reply) => {
    const domain = (req.query.domain || '').toString();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    if (rateLimited(req.ip)) {
      return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    }
    return analyzeDomain(domain, { resolver });
  });

  // Authentication health only (SPF / DKIM / DMARC / MX / PTR).
  app.get('/api/auth', async (req, reply) => {
    const domain = (req.query.domain || '').toString().trim();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    if (rateLimited(req.ip)) {
      return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    }
    // Guard: only [a-z0-9.-] hostnames / selectors are ever embedded in a DNS
    // name, so arbitrary input can't be used to craft odd lookups.
    const HOST_RE = /^[a-z0-9.-]{1,253}$/i;
    const host = domain.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/?#]/)[0].replace(/^www\./i, '');
    if (!HOST_RE.test(host)) return reply.code(400).send({ ok: false, error: 'invalid domain' });
    const sel = req.query.selector ? req.query.selector.toString() : null;
    if (sel && !HOST_RE.test(sel)) return reply.code(400).send({ ok: false, error: 'invalid selector' });
    return { ok: true, domain: host, ...(await checkAuth(host, { resolver, selectors: sel ? [sel] : undefined })) };
  });

  // Check history for a domain — only when a database is configured.
  app.get('/api/history', async (req, reply) => {
    if (!dbEnabled()) return reply.code(501).send({ ok: false, error: 'history requires DATABASE_URL' });
    const domain = (req.query.domain || '').toString().trim();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    const limit = Math.min(Number(req.query.limit ?? 20), 100);
    const rows = await db.checks.listChecksForDomain(domain, { limit });
    return { ok: true, domain: domain.toLowerCase(), count: rows.length, checks: rows };
  });

  app.get('/api/check', async (req, reply) => {
    const domain = (req.query.domain || '').toString();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });

    if (rateLimited(req.ip)) {
      return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    }

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

    // Charge the rate limiter in proportion to the work (each domain fans out
    // to ~100 DNS queries) so bulk can't be used to amplify load.
    const cost = Math.min(1 + Math.ceil(Math.min(inputs.length, BULK_MAX) / 25), RATE_MAX);
    if (rateLimited(req.ip, cost)) {
      return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    }

    const { results, summary, skipped } = await checkMany(inputs, {
      resolver,
      concurrency: BULK_CONCURRENCY,
      max: BULK_MAX,
      checkFn: checkCached,
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
