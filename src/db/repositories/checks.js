import { query, withTransaction } from '../pool.js';
import { upsertDomain } from './domains.js';

const COLS = 'id, domain_id, user_id, score, verdict, listed_count, raw_result, created_at';

/**
 * Persist one check result. `result` is the object returned by checkDomain():
 * we resolve/create the domain row, insert the check, and stamp the domain's
 * last_checked_at. All in a single transaction.
 *
 * @param {object} result  checkDomain() output (must be ok:true)
 * @param {object} [opts]  { userId }
 */
export async function saveCheck(result, { userId = null } = {}) {
  if (!result || !result.ok) throw new Error('cannot save an invalid check result');

  return withTransaction(async (client) => {
    const domName = result.domain;
    const dom = (
      await client.query(
        `INSERT INTO domains (name) VALUES ($1)
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
         RETURNING id`,
        [domName],
      )
    ).rows[0];

    const inserted = (
      await client.query(
        `INSERT INTO checks (domain_id, user_id, score, verdict, listed_count, raw_result)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING ${COLS}`,
        // Both result shapes land here: checkDomain() carries listedCount,
        // the bulk audit shape carries counts.listed.
        [dom.id, userId, result.score, result.verdict, result.listedCount ?? result.counts?.listed ?? 0, result],
      )
    ).rows[0];

    await client.query('UPDATE domains SET last_checked_at = now() WHERE id = $1', [dom.id]);
    return inserted;
  });
}

export async function getCheckById(id) {
  const { rows } = await query(`SELECT ${COLS} FROM checks WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

/** Check history for a domain (by name), newest first. */
export async function listChecksForDomain(name, { limit = 20, offset = 0 } = {}) {
  const { rows } = await query(
    `SELECT c.${COLS.split(', ').join(', c.')}
       FROM checks c JOIN domains d ON d.id = c.domain_id
      WHERE d.name = $1
      ORDER BY c.created_at DESC
      LIMIT $2 OFFSET $3`,
    [String(name).trim().toLowerCase(), limit, offset],
  );
  return rows;
}

/** A user's recent checks across all domains (v2 "history"). */
export async function listChecksForUser(userId, { limit = 20, offset = 0 } = {}) {
  const { rows } = await query(
    `SELECT c.id, c.domain_id, d.name AS domain, c.score, c.verdict,
            c.listed_count, c.created_at
       FROM checks c JOIN domains d ON d.id = c.domain_id
      WHERE c.user_id = $1
      ORDER BY c.created_at DESC
      LIMIT $2 OFFSET $3`,
    [userId, limit, offset],
  );
  return rows;
}

/** The latest check for a domain (used to diff for monitoring alerts). */
export async function latestCheckForDomain(domainId) {
  const { rows } = await query(
    `SELECT ${COLS} FROM checks WHERE domain_id = $1 ORDER BY created_at DESC LIMIT 1`,
    [domainId],
  );
  return rows[0] ?? null;
}

/** Count today's checks for a user. Enforces the free-tier daily quota. */
export async function countChecksToday(userId) {
  const { rows } = await query(
    `SELECT count(*)::int AS n FROM checks
      WHERE user_id = $1 AND created_at >= date_trunc('day', now())`,
    [userId],
  );
  return rows[0].n;
}

// Re-export so callers can register a domain without a full check.
export { upsertDomain };
