import { existsSync, readFileSync } from 'node:fs';

/**
 * Load a .env file into process.env so settings (like DBC_RESOLVERS or
 * DATABASE_URL) can be set once in a file instead of typed before every run.
 * Existing environment variables are NOT overwritten. No-op if .env is absent.
 *
 * Uses the built-in process.loadEnvFile when available (Node 20.12+/21.7+),
 * with a tiny hand-rolled parser as a fallback for older runtimes.
 */
export function loadEnv(path = '.env') {
  if (!existsSync(path)) return;
  try {
    if (typeof process.loadEnvFile === 'function') {
      process.loadEnvFile(path);
      return;
    }
  } catch {
    /* fall through to manual parse */
  }
  try {
    for (const raw of readFileSync(path, 'utf8').split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      let val = line.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (key && process.env[key] === undefined) process.env[key] = val;
    }
  } catch {
    /* ignore malformed .env */
  }
}
