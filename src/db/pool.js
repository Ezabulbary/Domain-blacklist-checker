import { readFileSync } from 'node:fs';
import pg from 'pg';

const { Pool } = pg;

// TLS config for the DB connection. TLS is enabled with DATABASE_SSL=true and,
// by default, the server certificate IS verified. Managed providers (Supabase
// and friends) sign with their own CA, which Node does not trust out of the
// box; give it to DATABASE_CA either as a file path or as the PEM text itself
// (handy on hosts like Render where an env var is easier than a file; literal
// \n sequences are unescaped). Verification can only be turned off with an
// explicit DATABASE_SSL_INSECURE=true. Never silently.
export function sslConfig(env = process.env) {
  if (env.DATABASE_SSL !== 'true') return undefined;
  if (env.DATABASE_SSL_INSECURE === 'true') {
    // eslint-disable-next-line no-console
    console.warn('[db] DATABASE_SSL_INSECURE=true. Server certificate verification is DISABLED');
    return { rejectUnauthorized: false };
  }
  const ssl = { rejectUnauthorized: true };
  if (env.DATABASE_CA) {
    const v = env.DATABASE_CA.trim();
    ssl.ca = v.includes('-----BEGIN') ? v.replace(/\\n/g, '\n') : readFileSync(v, 'utf8');
  }
  return ssl;
}

/**
 * A human-actionable hint for a known database error, or null. Surfaced by
 * /api/health next to the raw message, because "self-signed certificate in
 * certificate chain" alone sends the operator down the wrong road (the fix is
 * a CA setting, not a certificate problem on their side).
 */
export function dbErrorHint(message) {
  if (/self[- ]signed certificate/i.test(message || '')) {
    return 'The database uses its provider\'s own CA. Set DATABASE_CA to that CA certificate '
      + '(Supabase: Project Settings, Database, SSL, download the CA cert; pass a file path or paste the PEM itself), then restart. '
      + 'DATABASE_SSL_INSECURE=true also works but disables verification; use it only as a last resort.';
  }
  return null;
}

// pg returns BIGINT (OID 20) as a string by default to avoid precision loss.
// Our ids fit safely in a JS number, and returning strings would leak into the
// API, so parse them back to numbers.
pg.types.setTypeParser(20, (v) => (v === null ? null : Number(v)));

let pool = null;

/**
 * Lazily create the shared connection pool from DATABASE_URL. Returns null when
 * no DATABASE_URL is configured, so the rest of the app can run DB-less (the
 * MVP web/CLI path does not require Postgres).
 *
 *   DATABASE_URL=postgres://user:pass@host:5432/dbname
 *   DATABASE_SSL=true   -> enable TLS (managed providers)
 */
export function getPool() {
  if (pool) return pool;
  const url = process.env.DATABASE_URL;
  if (!url) return null;

  pool = new Pool({
    connectionString: url,
    max: Number(process.env.DATABASE_POOL_MAX ?? 10),
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: Number(process.env.DATABASE_CONNECT_TIMEOUT_MS ?? 5_000),
    ssl: sslConfig(),
  });

  // A pool error (e.g. the DB restarting) must not crash the process.
  pool.on('error', (err) => {
    // eslint-disable-next-line no-console
    console.error('[db] idle client error:', err.message);
  });

  return pool;
}

/** True when a database is configured. */
export const dbEnabled = () => Boolean(process.env.DATABASE_URL);

/** Convenience query helper. Throws if no DB is configured. */
export function query(text, params) {
  const p = getPool();
  if (!p) throw new Error('DATABASE_URL is not set');
  return p.query(text, params);
}

/**
 * Run `fn` inside a transaction, committing on success and rolling back on any
 * throw. `fn` receives a dedicated client.
 */
export async function withTransaction(fn) {
  const p = getPool();
  if (!p) throw new Error('DATABASE_URL is not set');
  const client = await p.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

/** Close the pool (tests / graceful shutdown). */
export async function closePool() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
