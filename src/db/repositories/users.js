import { randomBytes } from 'node:crypto';
import { query } from '../pool.js';

const COLS = 'id, email, plan, api_key, created_at, updated_at';

/** Generate an API key (hex, matches the DB default format). */
export const generateApiKey = () => randomBytes(24).toString('hex');

/**
 * Create a user. Email is stored as given but uniqueness is case-insensitive
 * (see the lower(email) index). Returns the created row.
 * Throws on duplicate email (Postgres error code 23505).
 */
export async function createUser({ email, plan = 'free', apiKey } = {}) {
  const { rows } = await query(
    `INSERT INTO users (email, plan, api_key)
     VALUES ($1, $2, COALESCE($3, encode(gen_random_bytes(24), 'hex')))
     RETURNING ${COLS}`,
    [email, plan, apiKey ?? null],
  );
  return rows[0];
}

export async function getUserById(id) {
  const { rows } = await query(`SELECT ${COLS} FROM users WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

export async function getUserByEmail(email) {
  const { rows } = await query(`SELECT ${COLS} FROM users WHERE lower(email) = lower($1)`, [email]);
  return rows[0] ?? null;
}

/** Look up a user by API key — the auth path for the REST API (v2). */
export async function getUserByApiKey(apiKey) {
  const { rows } = await query(`SELECT ${COLS} FROM users WHERE api_key = $1`, [apiKey]);
  return rows[0] ?? null;
}

/** Idempotent get-or-create by email. */
export async function upsertUserByEmail({ email, plan = 'free' } = {}) {
  const { rows } = await query(
    `INSERT INTO users (email, plan)
     VALUES ($1, $2)
     ON CONFLICT (lower(email)) DO UPDATE SET email = EXCLUDED.email
     RETURNING ${COLS}`,
    [email, plan],
  );
  return rows[0];
}

/** Change a user's plan (free/pro/agency). */
export async function setUserPlan(id, plan) {
  const { rows } = await query(
    `UPDATE users SET plan = $2 WHERE id = $1 RETURNING ${COLS}`,
    [id, plan],
  );
  return rows[0] ?? null;
}

/** Rotate the API key. */
export async function rotateApiKey(id, apiKey = generateApiKey()) {
  const { rows } = await query(
    `UPDATE users SET api_key = $2 WHERE id = $1 RETURNING ${COLS}`,
    [id, apiKey],
  );
  return rows[0] ?? null;
}

export async function deleteUser(id) {
  const { rowCount } = await query('DELETE FROM users WHERE id = $1', [id]);
  return rowCount > 0;
}
