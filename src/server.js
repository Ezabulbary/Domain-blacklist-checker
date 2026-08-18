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
import { createApiKey, validateApiKey, listApiKeys, revokeApiKey } from './lib/apikeys.js';
import { SCOPES, ALL_SCOPE, hasScope, normalizeScopes } from './lib/scopes.js';
import { getCalibration, isTrusted, summarize } from './lib/calibrate.js';
import { removalGuide, KIND_LABEL } from './lib/removal.js';
import { readiness, stillListed } from './lib/delist.js';
import { createShare, getShare, MAX_BYTES as SHARE_MAX_BYTES } from './lib/share.js';
import { login, getSession, destroySession } from './lib/sessions.js';
import { buildResolver } from './lib/resolve.js';
import { ALL_ZONES, CATEGORIES } from './lib/zones.js';
import { dbEnabled } from './db/pool.js';
import { db } from './db/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// One shared resolver for the process (see resolve.js for DBC_RESOLVERS).
const resolver = buildResolver();

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
async function authOk(req, reply, scope) {
  const key = (req.headers['x-api-key'] || req.query.api_key || '').toString().trim();
  if (!key) {
    if (REQUIRE_KEY) {
      reply.code(401).send({ ok: false, error: 'API key required. Send it as the X-API-Key header' });
      return false;
    }
    if (LOGIN_DISABLED) return true;
    // Browser path: a logged-in session instead of a key.
    const sess = sessionOf(req);
    if (!sess) {
      reply.code(401).send({ ok: false, error: 'login required', login: true });
      return false;
    }
    // CSRF: SameSite=Lax already keeps the cookie off cross-site POSTs; on top
    // of that, any state-changing request that carries an Origin must name us.
    if (req.method !== 'GET' && req.headers.origin) {
      let originHost = null;
      try { originHost = new URL(req.headers.origin).host; } catch { /* malformed */ }
      if (originHost !== req.headers.host) {
        reply.code(403).send({ ok: false, error: 'cross-origin request refused' });
        return false;
      }
    }
    // Key management is the admin's alone (the operator reversed the earlier
    // open policy). Everything else both roles can do.
    if (scope === 'keys:write' && sess.role !== 'admin') {
      reply.code(403).send({ ok: false, error: 'only the admin account can manage API keys' });
      return false;
    }
    req.user = sess.user;
    req.role = sess.role;
    return true;
  }
  let v;
  try {
    v = await validateApiKey(key);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[auth] key verification failed:', e.message);
    reply.code(503).send({ ok: false, error: 'the server cannot verify API keys right now (database unreachable). Try again shortly, or retry without a key.' });
    return false;
  }
  if (!v) {
    reply.code(401).send({ ok: false, error: 'invalid API key' });
    return false;
  }
  if (scope && !hasScope(v.scopes, scope)) {
    // 403, not 401: the key is valid, it simply was not created for this.
    reply.code(403).send({
      ok: false,
      error: `this API key is missing the "${scope}" scope`,
      required: scope,
      granted: v.scopes,
      hint: `Create a key that includes "${scope}", or "${ALL_SCOPE}" for full access.`,
    });
    return false;
  }
  req.apiKey = key;
  req.apiPlan = v.plan;
  req.apiScopes = v.scopes;
  req.apiKeyId = v.keyId;
  req.apiUserId = v.userId ?? null;
  return true;
}

// Rate-limit a request, bucketed and budgeted by whether it's authenticated.
function limited(req, cost = 1) {
  return req.apiKey
    ? rateLimited('k:' + req.apiKey, cost, RATE_MAX_KEYED)
    : rateLimited(req.ip, cost, RATE_MAX);
}

// The dashboard requires a login (two fixed accounts, see sessions.js). Set
// DBC_LOGIN_DISABLED=true to run the old open mode, e.g. for an embedded
// deployment that has its own auth in front.
const LOGIN_DISABLED = process.env.DBC_LOGIN_DISABLED === 'true';
const COOKIE = 'dbc_sid';

function cookieVal(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

function setSessionCookie(reply, id, maxAgeSeconds) {
  // HttpOnly: no script can read it. SameSite=Lax: browsers do not attach it to
  // cross-site POSTs, which closes most CSRF on its own (the Origin check in
  // authOk covers the rest). Secure when explicitly behind HTTPS.
  const secure = process.env.DBC_COOKIE_SECURE === 'true' ? '; Secure' : '';
  reply.header('set-cookie', `${COOKIE}=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`);
}

function clearSessionCookie(reply) {
  reply.header('set-cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

/** The live session on this request, or null. */
function sessionOf(req) {
  const sid = cookieVal(req, COOKIE);
  return sid ? getSession(sid) : null;
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

  // Accept raw text / CSV bodies (paste a list or upload a .csv/.txt).
  const rawParser = (_req, body, done) => done(null, body);
  app.addContentTypeParser('text/plain', { parseAs: 'string' }, rawParser);
  app.addContentTypeParser('text/csv', { parseAs: 'string' }, rawParser);

  app.register(fastifyStatic, {
    root: join(__dirname, '..', 'public'),
    prefix: '/',
  });

  // Baseline security headers on every response, static files included.
  app.addHook('onSend', (req, reply, payload, done) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('x-frame-options', 'DENY');
    reply.header('referrer-policy', 'no-referrer');
    done(null, payload);
  });

  // ---- Login (two fixed accounts, roles admin and user; see sessions.js) ----
  app.post('/api/login', async (req, reply) => {
    // Brute force is the whole threat model of a fixed-credential login, so
    // attempts are tightly rate-limited per IP, well below the global budget.
    if (rateLimited('login:' + req.ip, 1, 10)) {
      return reply.code(429).send({ ok: false, error: 'too many login attempts, wait a minute' });
    }
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    const s = login(body.username, body.password);
    if (!s) {
      // One generic message. Saying which field was wrong helps only attackers.
      return reply.code(401).send({ ok: false, error: 'wrong username or password' });
    }
    setSessionCookie(reply, s.id, s.maxAgeSeconds);
    return { ok: true, user: s.user, role: s.role };
  });

  app.post('/api/logout', async (req, reply) => {
    const sid = cookieVal(req, COOKIE);
    if (sid) destroySession(sid);
    clearSessionCookie(reply);
    return { ok: true };
  });

  // Who am I. Public on purpose: the page asks this before deciding whether to
  // show the login screen, and it reveals nothing an attacker can use.
  app.get('/api/me', async (req) => {
    if (LOGIN_DISABLED) return { ok: true, loginEnabled: false, authenticated: true, user: 'open', role: 'admin' };
    const sess = sessionOf(req);
    return sess
      ? { ok: true, loginEnabled: true, authenticated: true, user: sess.user, role: sess.role }
      : { ok: true, loginEnabled: true, authenticated: false };
  });

  app.get('/api/health', async () => ({ status: 'ok', zones: ALL_ZONES.length, db: dbEnabled() }));

  app.get('/api/zones', async (req, reply) => {
    if (!(await authOk(req, reply, 'zones:read'))) return;
    return {
    count: ALL_ZONES.length,
    categories: CATEGORIES,
    // `weight` is deliberately not exposed: severity says how bad a listing is
    // in words, and the exact scoring split stays server-side.
    zones: ALL_ZONES.map(({ name, zone, type, category, severity, status, note }) => ({
      name, zone, type, category, severity, status, note,
    })),
    };
  });

  // Which blocklists can be trusted from THIS server, and why not (see
  // calibrate.js). ?refresh=1 re-runs the probes.
  app.get('/api/calibration', async (req, reply) => {
    if (!(await authOk(req, reply, 'zones:read'))) return;
    const cal = await getCalibration({ resolver, force: req.query.refresh === '1' });
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
    if (!(await authOk(req, reply, 'removal:read'))) return;
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

  // Start an assisted removal: check from DNS whether the sender meets what the
  // list requires, and hand back a prefilled removal URL.
  app.get('/api/delist/start', async (req, reply) => {
    if (!(await authOk(req, reply, 'removal:read'))) return;
    const zone = (req.query.zone || '').toString().trim();
    const subject = (req.query.subject || '').toString().trim().split(',')[0].trim();
    const domain = (req.query.domain || '').toString().trim() || null;
    if (!zone || !subject) return reply.code(400).send({ ok: false, error: 'zone and subject are required' });
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    const z = ALL_ZONES.find((x) => x.zone === zone);
    if (!z) return reply.code(404).send({ ok: false, error: 'unknown blocklist' });
    return { ok: true, name: z.name, ...(await readiness({ zone, subject, domain }, resolver)) };
  });

  // Poll after submitting: has the entry actually gone?
  app.get('/api/delist/status', async (req, reply) => {
    if (!(await authOk(req, reply, 'removal:read'))) return;
    const zone = (req.query.zone || '').toString().trim();
    const subject = (req.query.subject || '').toString().trim();
    if (!zone || !subject) return reply.code(400).send({ ok: false, error: 'zone and subject are required' });
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    const listed = await stillListed(zone, subject, resolver);
    return { ok: true, zone, subject, listed, checkedAt: new Date().toISOString() };
  });

  // Freeze a result as a shareable snapshot. Anyone with the link can view it
  // at /r/<id>; the id is 128 random bits and the only secret.
  app.post('/api/share', async (req, reply) => {
    if (!(await authOk(req, reply))) return;
    if (limited(req, 2)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    try {
      const r = await createShare(body.kind, body.data);
      return {
        ok: true,
        id: r.id,
        url: '/r/' + r.id,
        expiresAt: r.expiresAt,
        persisted: r.persisted,
        note: r.persisted
          ? null
          : r.dbFailed
            ? 'The configured database could not be reached, so this link is held in memory and dies when the server restarts. Check DATABASE_URL in .env.'
            : 'No database is configured, so this link is held in memory and dies when the server restarts. Set DATABASE_URL to keep share links.',
      };
    } catch (e) {
      if (/kind|object|too large/.test(e.message)) {
        return reply.code(400).send({ ok: false, error: e.message, maxBytes: SHARE_MAX_BYTES });
      }
      req.log?.error?.(e);
      return reply.code(500).send({ ok: false, error: 'could not save the snapshot, try again shortly' });
    }
  });

  app.get('/api/share/:id', async (req, reply) => {
    const snap = await getShare(req.params.id);
    if (!snap) return reply.code(404).send({ ok: false, error: 'this link does not exist or has expired' });
    return { ok: true, kind: snap.kind, data: snap.payload, createdAt: snap.createdAt, expiresAt: snap.expiresAt };
  });

  // The share page itself is the normal UI; it reads the id from the path and
  // fetches the snapshot instead of running a live check.
  app.get('/r/:id', (req, reply) => reply.sendFile('index.html'));

  // The scope catalog, so the create form and the docs stay in step with the
  // server rather than drifting from a hardcoded copy.
  app.get('/api/scopes', async (req, reply) => {
    if (!(await authOk(req, reply, 'keys:write'))) return;
    return { ok: true, all: ALL_SCOPE, scopes: SCOPES };
  });

  // Create an API key. Body: { name, scopes: [...], email? }
  // The key is returned exactly once and is never stored, only its hash.
  app.post('/api/keys', async (req, reply) => {
    if (!(await authOk(req, reply, 'keys:write'))) return;
    if (rateLimited(req.ip, 5)) {
      return reply.code(429).send({ ok: false, error: 'too many key requests, slow down' });
    }
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    const name = typeof body.name === 'string' ? body.name.trim().slice(0, 120) : '';
    if (!name) return reply.code(400).send({ ok: false, error: 'name is required' });

    // Reject an unknown scope rather than quietly issuing a key with less access
    // than was asked for. Silently dropping a scope produces a key that fails
    // later, somewhere else, for reasons nobody can see.
    const { scopes, invalid } = normalizeScopes(body.scopes ?? [ALL_SCOPE]);
    if (invalid.length) {
      return reply.code(400).send({
        ok: false,
        error: `unknown scope: ${invalid.join(', ')}`,
        valid: [ALL_SCOPE, ...SCOPES.map((x) => x.key)],
      });
    }
    if (!scopes.length) return reply.code(400).send({ ok: false, error: 'select at least one scope' });

    try {
      const r = await createApiKey({ name, scopes, email: body.email });
      return {
        ok: true,
        apiKey: r.apiKey,
        key: r.key,
        persisted: r.persisted,
        requireKey: REQUIRE_KEY,
        note: r.persisted
          ? 'Copy this key now. It is stored only as a hash and cannot be shown again.'
          : r.dbFailed
            ? 'Copy this key now. The configured database could not be reached, so this key is held in memory and stops working when the server restarts. Check DATABASE_URL in .env.'
            : 'Copy this key now. It cannot be shown again, and with no DATABASE_URL configured it is held in memory and lost on restart.',
      };
    } catch (e) {
      req.log?.error?.(e);
      return reply.code(500).send({ ok: false, error: 'could not create the key, try again shortly' });
    }
  });

  // List keys. Never returns a key, only its prefix and what it can do.
  app.get('/api/keys', async (req, reply) => {
    if (!(await authOk(req, reply, 'keys:write'))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    return { ok: true, keys: await listApiKeys(req.apiUserId ?? null) };
  });

  // Revoke a key. Revoked rather than deleted, so the audit trail survives.
  app.delete('/api/keys/:id', async (req, reply) => {
    if (!(await authOk(req, reply, 'keys:write'))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    const row = await revokeApiKey(req.params.id);
    if (!row) return reply.code(404).send({ ok: false, error: 'key not found, or already revoked' });
    return { ok: true, key: row };
  });

  // Unified deliverability report (blacklists + auth + risk + recommendations).
  app.get('/api/analyze', async (req, reply) => {
    const domain = (req.query.domain || '').toString();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    if (!(await authOk(req, reply, 'analyze:read'))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    return analyzeDomain(domain, { resolver });
  });

  // Authentication health only (SPF / DKIM / DMARC / MX / PTR).
  app.get('/api/auth', async (req, reply) => {
    const domain = (req.query.domain || '').toString().trim();
    if (!domain) return reply.code(400).send({ ok: false, error: 'missing ?domain=' });
    if (!(await authOk(req, reply, 'auth:read'))) return;
    if (limited(req)) return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    // Guard: only [a-z0-9.-] hostnames / selectors are ever embedded in a DNS
    // name, so arbitrary input can't be used to craft odd lookups.
    const HOST_RE = /^[a-z0-9.-]{1,253}$/i;
    const host = domain.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/?#]/)[0].replace(/^www\./i, '');
    if (!HOST_RE.test(host)) return reply.code(400).send({ ok: false, error: 'invalid domain' });
    const sel = req.query.selector ? req.query.selector.toString() : null;
    if (sel && !HOST_RE.test(sel)) return reply.code(400).send({ ok: false, error: 'invalid selector' });
    return { ok: true, domain: host, ...(await checkAuth(host, { resolver, selectors: sel ? [sel] : undefined })) };
  });

  // Check history for a domain. Only when a database is configured.
  app.get('/api/history', async (req, reply) => {
    // Authorize before saying anything about this endpoint's state. Answering
    // "not implemented" to a key that was never allowed here tells an
    // unauthorized caller about the deployment.
    if (!(await authOk(req, reply, 'history:read'))) return;
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
    if (!(await authOk(req, reply, 'check:read'))) return;
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
    if (!(await authOk(req, reply, 'bulk:write'))) return;

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
