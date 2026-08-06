import { query } from '../pool.js';

// Rows never carry key_hash outward. The hash is only ever a lookup input.
const COLS = 'id, user_id, name, key_prefix, scopes, last_used_at, revoked_at, created_at';

export async function createKey({ userId = null, name, keyHash, keyPrefix, scopes }) {
  const { rows } = await query(
    `INSERT INTO api_keys (user_id, name, key_hash, key_prefix, scopes)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING ${COLS}`,
    [userId, name, keyHash, keyPrefix, scopes],
  );
  return rows[0];
}

/** Find a live key by the hash of the presented secret. */
export async function getByHash(keyHash) {
  const { rows } = await query(
    `SELECT ${COLS} FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL`,
    [keyHash],
  );
  return rows[0] ?? null;
}

/**
 * Stamp last use. Deliberately not awaited on the request path: a slow write
 * here would slow down every authenticated call, and losing one timestamp
 * matters less than that.
 */
export async function touch(id) {
  await query('UPDATE api_keys SET last_used_at = now() WHERE id = $1', [id]);
}

export async function listKeys(userId = null) {
  const { rows } = await query(
    `SELECT ${COLS} FROM api_keys
     WHERE ($1::bigint IS NULL OR user_id = $1)
     ORDER BY created_at DESC`,
    [userId],
  );
  return rows;
}

/** Revoke rather than delete, so an audit trail survives. */
export async function revokeKey(id) {
  const { rows } = await query(
    `UPDATE api_keys SET revoked_at = now()
     WHERE id = $1 AND revoked_at IS NULL
     RETURNING ${COLS}`,
    [id],
  );
  return rows[0] ?? null;
}
