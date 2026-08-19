import { query } from '../pool.js';

/**
 * Mirror one in-memory visitor record to the database. Called on every
 * heartbeat (each browser beats about twice a minute, so this stays cheap).
 * The record's own timestamps win, so a restore reads back exactly what the
 * page showed.
 */
export async function saveVisitor(rec) {
  await query(
    `INSERT INTO visitors (id, first_seen, last_seen, hits, data)
     VALUES ($1, to_timestamp($2 / 1000.0), to_timestamp($3 / 1000.0), $4, $5)
     ON CONFLICT (id) DO UPDATE SET
       last_seen = EXCLUDED.last_seen,
       hits      = EXCLUDED.hits,
       data      = EXCLUDED.data`,
    [rec.id, rec.firstSeen, rec.lastSeen, rec.hits, rec],
  );
}

/**
 * Read back stored visitor records, newest first, as the plain objects the
 * presence store keeps in memory. Used once at boot to rehydrate.
 */
export async function listStoredVisitors({ limit = 500 } = {}) {
  const { rows } = await query(
    'SELECT data FROM visitors ORDER BY last_seen DESC LIMIT $1',
    [limit],
  );
  return rows.map((r) => r.data);
}
