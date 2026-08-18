import { query } from '../pool.js';

export async function createShare({ id, kind, payload, ttlDays }) {
  const { rows } = await query(
    `INSERT INTO shared_reports (id, kind, payload, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(days => $4))
     RETURNING id, kind, created_at, expires_at`,
    [id, kind, payload, ttlDays],
  );
  return rows[0];
}

export async function getShare(id) {
  // Expiry enforced in the query, so an expired link is simply gone; a
  // background delete pass is tidiness, not correctness.
  const { rows } = await query(
    `SELECT id, kind, payload, created_at, expires_at
     FROM shared_reports WHERE id = $1 AND expires_at > now()`,
    [id],
  );
  return rows[0] ?? null;
}

/** Drop expired snapshots. Called opportunistically, never on the read path. */
export async function sweepShares() {
  const { rowCount } = await query('DELETE FROM shared_reports WHERE expires_at <= now()');
  return rowCount;
}
