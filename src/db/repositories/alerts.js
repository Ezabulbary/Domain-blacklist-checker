import { query } from '../pool.js';

const COLS = 'id, monitor_id, zone, subject, status_change, created_at, notified_at';

/**
 * Record a reputation change for a monitor.
 * @param {object} a { monitorId, zone, subject?, statusChange: 'listed'|'delisted' }
 */
export async function createAlert({ monitorId, zone, subject = null, statusChange } = {}) {
  const { rows } = await query(
    `INSERT INTO alerts (monitor_id, zone, subject, status_change)
     VALUES ($1, $2, $3, $4)
     RETURNING ${COLS}`,
    [monitorId, zone, subject, statusChange],
  );
  return rows[0];
}

/**
 * Diff two check results and record one alert per zone that flipped
 * listed<->clean for the given monitor. Returns the created alert rows.
 *
 * @param {number} monitorId
 * @param {object|null} previous  earlier checkDomain() result (or null = first run)
 * @param {object} current        latest checkDomain() result
 */
export async function recordChanges(monitorId, previous, current) {
  const key = (l) => `${l.subject}|${l.zone}`;
  const prev = new Set((previous?.listings ?? []).map(key));
  const curr = new Map((current.listings ?? []).map((l) => [key(l), l]));

  const created = [];
  // Newly listed.
  for (const [k, l] of curr) {
    if (!prev.has(k)) {
      created.push(await createAlert({ monitorId, zone: l.zone, subject: l.subject, statusChange: 'listed' }));
    }
  }
  // Newly delisted.
  for (const l of previous?.listings ?? []) {
    if (!curr.has(key(l))) {
      created.push(await createAlert({ monitorId, zone: l.zone, subject: l.subject, statusChange: 'delisted' }));
    }
  }
  return created;
}

/** Alert feed for a monitor, newest first. */
export async function listAlertsForMonitor(monitorId, { limit = 50, offset = 0 } = {}) {
  const { rows } = await query(
    `SELECT ${COLS} FROM alerts WHERE monitor_id = $1
      ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
    [monitorId, limit, offset],
  );
  return rows;
}

/** Alerts awaiting a notification (the outbox the notifier drains). */
export async function listUnnotifiedAlerts({ limit = 100 } = {}) {
  const { rows } = await query(
    `SELECT ${COLS} FROM alerts WHERE notified_at IS NULL
      ORDER BY created_at LIMIT $1`,
    [limit],
  );
  return rows;
}

/** Mark alerts as notified after the email/Slack send succeeds. */
export async function markAlertsNotified(ids) {
  if (!ids || ids.length === 0) return 0;
  const { rowCount } = await query(
    `UPDATE alerts SET notified_at = now() WHERE id = ANY($1::bigint[])`,
    [ids],
  );
  return rowCount;
}
