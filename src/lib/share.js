import { randomBytes } from 'node:crypto';
import { dbEnabled } from '../db/pool.js';
import { db } from '../db/index.js';

// Shareable result snapshots.
//
// A result (single analyze, or a finished bulk table) is frozen under a random
// id; /r/<id> renders it for whoever holds the link. The id is the whole
// secret: 128 random bits, no listing, nothing sequential to walk.
//
// With a database the snapshot survives restarts and expires after TTL days.
// Without one it lives in memory, capped, and the API says so, because a link
// that quietly dies on restart erodes exactly the trust it was meant to build.

const TTL_DAYS = Number(process.env.DBC_SHARE_TTL_DAYS ?? 90);
const MEM_MAX = Number(process.env.DBC_SHARE_MEM_MAX ?? 500);
// A snapshot is stored verbatim, so it needs a hard size cap: one oversized
// bulk share must not evict everything else or balloon the process.
export const MAX_BYTES = Number(process.env.DBC_SHARE_MAX_BYTES ?? 1.5 * 1024 * 1024);

const mem = new Map(); // id -> { kind, payload, createdAt, expiresAt }

export const newShareId = () => randomBytes(16).toString('hex');

const KINDS = new Set(['single', 'bulk']);

/**
 * Freeze a result. Returns { id, expiresAt, persisted } or throws on bad input.
 */
export async function createShare(kind, payload) {
  if (!KINDS.has(kind)) throw new Error('kind must be "single" or "bulk"');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('payload must be an object');
  }
  const bytes = Buffer.byteLength(JSON.stringify(payload));
  if (bytes > MAX_BYTES) {
    throw new Error(`snapshot too large (${Math.round(bytes / 1024)} KB, limit ${Math.round(MAX_BYTES / 1024)} KB)`);
  }

  const id = newShareId();
  if (dbEnabled()) {
    // A database that is configured but unreachable (bad DATABASE_URL, network
    // down, Supabase paused) must not take the feature down with it. The link
    // still gets created, in memory, and the response says so, instead of the
    // user seeing a raw resolver error where their link should be.
    try {
      const row = await db.shares.createShare({ id, kind, payload, ttlDays: TTL_DAYS });
      // Best-effort tidiness; correctness comes from the read-side expiry check.
      db.shares.sweepShares().catch(() => {});
      return { id: row.id, expiresAt: row.expires_at, persisted: true };
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[share] database write failed, keeping the snapshot in memory:', e.message);
      const expiresAt = new Date(Date.now() + TTL_DAYS * 86400_000).toISOString();
      mem.set(id, { kind, payload, createdAt: new Date().toISOString(), expiresAt });
      while (mem.size > MEM_MAX) mem.delete(mem.keys().next().value);
      // dbFailed lets the caller say "your database is broken", which is a
      // different problem from "you have not configured one".
      return { id, expiresAt, persisted: false, dbFailed: true };
    }
  }

  const expiresAt = new Date(Date.now() + TTL_DAYS * 86400_000).toISOString();
  mem.set(id, { kind, payload, createdAt: new Date().toISOString(), expiresAt });
  while (mem.size > MEM_MAX) mem.delete(mem.keys().next().value); // FIFO evict
  return { id, expiresAt, persisted: false };
}

/** Fetch a live snapshot, or null. */
export async function getShare(id) {
  if (!/^[0-9a-f]{32}$/.test(String(id || ''))) return null;
  if (dbEnabled()) {
    let row = null;
    let dbDown = false;
    try {
      row = await db.shares.getShare(id);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[share] database read failed, falling back to memory:', e.message);
      dbDown = true;
    }
    if (row) return { kind: row.kind, payload: row.payload, createdAt: row.created_at, expiresAt: row.expires_at };
    // The snapshot may live in memory: either it was created during an outage,
    // or the configured database was never reachable at all.
    if (!dbDown && !mem.has(id)) return null;
  }
  const m = mem.get(id);
  if (!m) return null;
  if (new Date(m.expiresAt).getTime() < Date.now()) {
    mem.delete(id);
    return null;
  }
  return { kind: m.kind, payload: m.payload, createdAt: m.createdAt, expiresAt: m.expiresAt };
}
