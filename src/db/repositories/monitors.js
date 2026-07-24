import { query } from '../pool.js';
import { upsertDomain } from './domains.js';

const COLS =
  'id, user_id, domain_id, frequency, notify_email, active, last_run_at, next_run_at, created_at, updated_at';

const INTERVAL = { hourly: '1 hour', daily: '1 day', weekly: '7 days' };

/**
 * Create (or return the existing) monitor for a user + domain name. The domain
 * is resolved/created first. One monitor per (user, domain) — a second call
 * updates frequency/notify_email/active instead of erroring.
 */
export async function createMonitor({ userId, domainName, frequency = 'daily', notifyEmail = null } = {}) {
  const dom = await upsertDomain(domainName);
  const { rows } = await query(
    `INSERT INTO monitors (user_id, domain_id, frequency, notify_email)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (user_id, domain_id) DO UPDATE
       SET frequency = EXCLUDED.frequency,
           notify_email = EXCLUDED.notify_email,
           active = true
     RETURNING ${COLS}`,
    [userId, dom.id, frequency, notifyEmail],
  );
  return rows[0];
}

export async function getMonitorById(id) {
  const { rows } = await query(`SELECT ${COLS} FROM monitors WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

/** All monitors for a user (with the domain name joined in), newest first. */
export async function listMonitorsForUser(userId, { activeOnly = false } = {}) {
  const { rows } = await query(
    `SELECT m.${COLS.split(', ').join(', m.')}, d.name AS domain
       FROM monitors m JOIN domains d ON d.id = m.domain_id
      WHERE m.user_id = $1 ${activeOnly ? 'AND m.active' : ''}
      ORDER BY m.created_at DESC`,
    [userId],
  );
  return rows;
}

export async function setMonitorActive(id, active) {
  const { rows } = await query(
    `UPDATE monitors SET active = $2 WHERE id = $1 RETURNING ${COLS}`,
    [id, active],
  );
  return rows[0] ?? null;
}

export async function deleteMonitor(id) {
  const { rowCount } = await query('DELETE FROM monitors WHERE id = $1', [id]);
  return rowCount > 0;
}

/**
 * Claim monitors that are due to run (active and next_run_at <= now). Uses
 * FOR UPDATE SKIP LOCKED so multiple workers can poll concurrently without
 * grabbing the same rows. Advances next_run_at by the monitor's frequency and
 * stamps last_run_at so a row is never handed out twice for the same window.
 */
export async function claimDueMonitors({ limit = 50 } = {}) {
  const { rows } = await query(
    `WITH due AS (
       SELECT id FROM monitors
        WHERE active AND next_run_at <= now()
        ORDER BY next_run_at
        LIMIT $1
        FOR UPDATE SKIP LOCKED
     )
     UPDATE monitors m
        SET last_run_at = now(),
            next_run_at = now() + (CASE m.frequency
              WHEN 'hourly' THEN INTERVAL '${INTERVAL.hourly}'
              WHEN 'weekly' THEN INTERVAL '${INTERVAL.weekly}'
              ELSE INTERVAL '${INTERVAL.daily}' END)
       FROM due
      WHERE m.id = due.id
      RETURNING m.${COLS.split(', ').join(', m.')},
                (SELECT name FROM domains d WHERE d.id = m.domain_id) AS domain`,
    [limit],
  );
  return rows;
}
