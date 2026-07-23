import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { checkDomain } from './lib/check.js';
import { checkMany, resultsToCsv } from './lib/bulk.js';
import { buildResolver } from './lib/resolve.js';
import { ALL_ZONES } from './lib/zones.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// One shared resolver for the process (see resolve.js for DBC_RESOLVERS).
const resolver = buildResolver();

// Tiny in-memory cache so repeat lookups don't re-hammer the DNSBLs. In
// production this becomes Redis with a 15-30 min TTL (plan §5.3) — caching is
// mandatory, not optional, to stay inside free query limits.
const CACHE_TTL_MS = Number(process.env.DBC_CACHE_TTL_MS ?? 15 * 60 * 1000);
const cache = new Map(); // domain -> { at, value }

function cached(key) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
  cache.delete(key);
  return null;
}

// Very small fixed-window rate limiter per IP (plan §5.5) — protect our own IP
// from being blocked by the DNSBLs due to a caller's abuse.
const RATE_MAX = Number(process.env.DBC_RATE_MAX ?? 30);
const RATE_WINDOW_MS = Number(process.env.DBC_RATE_WINDOW_MS ?? 60 * 1000);
const hits = new Map(); // ip -> { count, resetAt }

function rateLimited(ip) {
  const now = Date.now();
  const rec = hits.get(ip);
  if (!rec || now > rec.resetAt) {
    hits.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return false;
  }
  rec.count += 1;
  return rec.count > RATE_MAX;
}

// Cache-aware single check, reused by both the single and bulk routes.
async function checkCached(domain, opts) {
  const key = domain.trim().toLowerCase();
  const hit = cached(key);
  if (hit) return { ...hit, cached: true };
  const result = await checkDomain(domain, opts);
  if (result.ok) cache.set(key, { at: Date.now(), value: result });
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
  });

  // Accept raw text / CSV bodies (paste a list or upload a .csv/.txt).
  const rawParser = (_req, body, done) => done(null, body);
  app.addContentTypeParser('text/plain', { parseAs: 'string' }, rawParser);
  app.addContentTypeParser('text/csv', { parseAs: 'string' }, rawParser);

  app.register(fastifyStatic, {
    root: join(__dirname, '..', 'public'),
    prefix: '/',
  });

  app.get('/api/health', async () => ({ status: 'ok', zones: ALL_ZONES.length }));

  app.get('/api/zones', async () => ({
    count: ALL_ZONES.length,
    zones: ALL_ZONES.map(({ zone, weight, severity, note }) => ({ zone, weight, severity, note })),
  }));

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
    if (rateLimited(req.ip)) {
      return reply.code(429).send({ ok: false, error: 'rate limit exceeded, slow down' });
    }

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
