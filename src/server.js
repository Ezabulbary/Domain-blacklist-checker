import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { checkDomain } from './lib/check.js';
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

export function buildServer() {
  const app = Fastify({ logger: process.env.NODE_ENV !== 'test' });

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

    const key = domain.trim().toLowerCase();
    const hit = cached(key);
    if (hit) return { ...hit, cached: true };

    const result = await checkDomain(domain, { resolver });
    if (result.ok) cache.set(key, { at: Date.now(), value: result });
    return { ...result, cached: false };
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
