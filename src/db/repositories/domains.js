import { query } from '../pool.js';

const COLS = 'id, name, first_seen, last_checked_at';

/**
 * Get-or-create a domain by its normalized (lowercase) registrable name.
 * `first_seen` is set once, on first insert. Returns the row either way.
 */
export async function upsertDomain(name) {
  const norm = String(name).trim().toLowerCase();
  const { rows } = await query(
    `INSERT INTO domains (name)
     VALUES ($1)
     ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
     RETURNING ${COLS}`,
    [norm],
  );
  return rows[0];
}

export async function getDomainById(id) {
  const { rows } = await query(`SELECT ${COLS} FROM domains WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

export async function getDomainByName(name) {
  const { rows } = await query(
    `SELECT ${COLS} FROM domains WHERE name = $1`,
    [String(name).trim().toLowerCase()],
  );
  return rows[0] ?? null;
}

/** Stamp last_checked_at = now() after a check runs. */
export async function touchDomainChecked(id) {
  const { rows } = await query(
    `UPDATE domains SET last_checked_at = now() WHERE id = $1 RETURNING ${COLS}`,
    [id],
  );
  return rows[0] ?? null;
}

/** Most recently seen domains (admin/overview). */
export async function listDomains({ limit = 50, offset = 0 } = {}) {
  const { rows } = await query(
    `SELECT ${COLS} FROM domains ORDER BY first_seen DESC LIMIT $1 OFFSET $2`,
    [limit, offset],
  );
  return rows;
}
