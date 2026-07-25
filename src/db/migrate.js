import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadEnv } from '../lib/env.js';
import { getPool, closePool } from './pool.js';

loadEnv();

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname, 'migrations');

/**
 * Apply every *.sql file in migrations/ that hasn't run yet, in filename order.
 * Each file runs inside a transaction and is recorded in schema_migrations, so
 * re-running only applies what's new. The SQL files are also individually
 * idempotent (IF NOT EXISTS), belt-and-suspenders.
 */
export async function migrate({ log = console.log } = {}) {
  const pool = getPool();
  if (!pool) throw new Error('DATABASE_URL is not set. Cannot migrate');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename    TEXT PRIMARY KEY,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const files = readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const { rows } = await pool.query('SELECT filename FROM schema_migrations');
  const done = new Set(rows.map((r) => r.filename));

  let applied = 0;
  for (const file of files) {
    if (done.has(file)) {
      log(`  = ${file} (already applied)`);
      continue;
    }
    const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations(filename) VALUES ($1)', [file]);
      await client.query('COMMIT');
      applied += 1;
      log(`  + ${file}`);
    } catch (e) {
      await client.query('ROLLBACK');
      throw new Error(`migration ${file} failed: ${e.message}`);
    } finally {
      client.release();
    }
  }

  log(applied === 0 ? 'Database already up to date.' : `Applied ${applied} migration(s).`);
  return applied;
}

// CLI entrypoint:  npm run db:migrate
const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is not set. Example:');
    console.error('  DATABASE_URL=postgres://postgres@127.0.0.1:5432/blacklist npm run db:migrate');
    process.exit(1);
  }
  try {
    await migrate();
  } catch (e) {
    console.error('✗', e.message);
    process.exitCode = 1;
  } finally {
    await closePool();
  }
}
