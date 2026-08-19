import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { dbEnabled } from '../db/pool.js';
import { db } from '../db/index.js';
import { normalizeScopes, ALL_SCOPE } from './scopes.js';

// API keys are OPTIONAL by default. The API works without one. A key
// authenticates you (higher rate limit, attribution) and carries scopes that
// bound what it can reach. The server can demand one with DBC_REQUIRE_KEY=true.
//
// The key is shown once, at creation, and never stored. What is stored is a
// SHA-256 hash plus a short non-secret prefix for display, so a database that
// leaks yields no usable keys.
//
// Without a database, keys live in memory so the feature still works for a demo
// and for tests. Those are lost on restart, and the API says so.

export const newKey = () => 'dbc_' + randomBytes(24).toString('hex');

const hash = (key) => createHash('sha256').update(String(key)).digest('hex');
// Enough to recognise a key in a list, not enough to use it.
const prefixOf = (key) => key.slice(0, 12);

const mem = new Map(); // keyHash -> { id, name, scopes, prefix, createdAt, revokedAt }
let memId = 0;

const publicRow = (r) => ({
  id: r.id,
  name: r.name,
  prefix: r.key_prefix ?? r.prefix,
  scopes: r.scopes,
  createdAt: r.created_at ?? r.createdAt,
  lastUsedAt: r.last_used_at ?? r.lastUsedAt ?? null,
  revokedAt: r.revoked_at ?? r.revokedAt ?? null,
  expiresAt: r.expires_at ?? r.expiresAt ?? null,
  useCount: r.use_count ?? r.useCount ?? 0,
  lastUsedIp: r.last_used_ip ?? r.lastUsedIp ?? null,
});

const isExpired = (row) => {
  const exp = row.expires_at ?? row.expiresAt;
  return Boolean(exp && new Date(exp).getTime() <= Date.now());
};

/**
 * Create a key.
 *
 * @param {object} opts
 *   name       what the key is for. Required in spirit, defaulted if absent.
 *   scopes     array of scope strings, or ['all:all']. Defaults to all:all so
 *              the old zero-argument call keeps its meaning.
 *   email      optional, ties the key to a user record.
 *   expiresAt  optional ISO timestamp or Date: the key stops working then.
 *              Absent = never expires. A bounded lifetime is the production
 *              default worth choosing; a leaked expiring key is a bounded
 *              problem.
 * @returns { apiKey, key: {...}, persisted, invalidScopes }
 */
export async function createApiKey({ name, scopes, email, expiresAt } = {}) {
  const apiKey = newKey();
  const keyHash = hash(apiKey);
  const keyPrefix = prefixOf(apiKey);
  const label = (name && String(name).trim()) || 'Unnamed key';
  const expIso = expiresAt ? new Date(expiresAt).toISOString() : null;

  const { scopes: clean, invalid } = normalizeScopes(scopes ?? [ALL_SCOPE]);
  // A key with no scopes could not call anything, which is never what someone
  // meant to build. Treat an empty selection as the default rather than
  // creating a key that is dead on arrival.
  const granted = clean.length ? clean : [ALL_SCOPE];

  if (dbEnabled()) {
    // A configured-but-unreachable database (bad DATABASE_URL, network down)
    // must not stop keys from being issued. The key falls back to the bounded
    // memory store and the response says so, instead of surfacing a raw
    // resolver error where the key should be.
    try {
      let userId = null;
      if (email && String(email).trim()) {
        const u = await db.users.upsertUserByEmail({ email: String(email).trim() });
        userId = u?.id ?? null;
      }
      const row = await db.apikeys.createKey({ userId, name: label, keyHash, keyPrefix, scopes: granted, expiresAt: expIso });
      return { apiKey, key: publicRow(row), persisted: true, invalidScopes: invalid };
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[keys] database write failed, keeping the key in memory:', e.message);
      const row = { id: ++memId, name: label, prefix: keyPrefix, scopes: granted, createdAt: new Date().toISOString(), revokedAt: null, expiresAt: expIso, useCount: 0 };
      mem.set(keyHash, row);
      return { apiKey, key: publicRow(row), persisted: false, dbFailed: true, invalidScopes: invalid };
    }
  }

  const row = { id: ++memId, name: label, prefix: keyPrefix, scopes: granted, createdAt: new Date().toISOString(), revokedAt: null, expiresAt: expIso, useCount: 0 };
  mem.set(keyHash, row);
  return { apiKey, key: publicRow(row), persisted: false, invalidScopes: invalid };
}

/**
 * Validate a presented key.
 * @param {string} apiKey
 * @param {object} [meta]  { ip } of the caller, recorded as usage.
 * @returns { scopes, keyId, name, plan, userId? }, { expired: true, ... } for
 *          a key past its lifetime (a distinct answer, so the caller can say
 *          "expired" rather than a misleading "invalid"), or null.
 */
export async function validateApiKey(apiKey, meta = {}) {
  if (!apiKey || typeof apiKey !== 'string') return null;
  const keyHash = hash(apiKey);

  const expiredAnswer = (r) => ({ expired: true, name: r.name, expiresAt: r.expires_at ?? r.expiresAt });
  const useMem = (m) => {
    if (m.revokedAt) return null;
    if (isExpired(m)) return expiredAnswer(m);
    m.useCount = (m.useCount || 0) + 1;
    m.lastUsedAt = new Date().toISOString();
    if (meta.ip) m.lastUsedIp = String(meta.ip).slice(0, 60);
    return { scopes: m.scopes, keyId: m.id, name: m.name, plan: 'free' };
  };

  if (dbEnabled()) {
    try {
      const row = await db.apikeys.getByHash(keyHash);
      if (row) {
        if (isExpired(row)) return expiredAnswer(row);
        // Best effort. A slow write here would tax every authenticated request.
        db.apikeys.touch(row.id, meta.ip ?? null).catch(() => {});
        return { scopes: row.scopes, keyId: row.id, name: row.name, userId: row.user_id, plan: 'free' };
      }
      // Legacy: a key issued before scopes existed, stored plainly on the user
      // row. Still honoured, with full access, so upgrading breaks nobody.
      const u = await db.users.getUserByApiKey(apiKey);
      if (u) return { scopes: [ALL_SCOPE], keyId: null, name: 'legacy key', userId: u.id, plan: u.plan, legacy: true };
    } catch (e) {
      // The database is unreachable. A key issued during the outage lives in
      // memory and still verifies; anything else genuinely cannot be checked,
      // and guessing either way (valid or invalid) would be wrong, so that
      // case stays a thrown error for the route to turn into a clear 503.
      // eslint-disable-next-line no-console
      console.error('[keys] database read failed, checking the memory store:', e.message);
      const m2 = mem.get(keyHash);
      // A key the memory store knows about has a definite answer even during
      // the outage: live keys verify, revoked and expired keys are refused.
      // Only a key with no record anywhere is genuinely unverifiable.
      if (m2) return useMem(m2);
      throw new Error('database unreachable, cannot verify this key');
    }
    // DB answered "no such key"; a memory key from an earlier outage may still
    // exist on this instance.
    const m3 = mem.get(keyHash);
    if (m3) return useMem(m3);
    return null;
  }

  const m = mem.get(keyHash);
  if (!m) return null;
  return useMem(m);
}

/** Count of live (unrevoked, unexpired) keys, for the creation cap. */
export async function countActiveKeys() {
  const rows = await listApiKeys();
  return rows.filter((r) => !r.revokedAt && !(r.expiresAt && new Date(r.expiresAt).getTime() <= Date.now())).length;
}

export async function listApiKeys(userId = null) {
  if (dbEnabled()) {
    try {
      return (await db.apikeys.listKeys(userId)).map(publicRow);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[keys] database list failed, listing memory keys:', e.message);
    }
  }
  return [...mem.values()].map(publicRow);
}

export async function revokeApiKey(id) {
  if (dbEnabled()) {
    try {
      const row = await db.apikeys.revokeKey(id);
      if (row) return publicRow(row);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[keys] database revoke failed, trying the memory store:', e.message);
    }
  }
  for (const [h, r] of mem) {
    if (String(r.id) === String(id) && !r.revokedAt) {
      r.revokedAt = new Date().toISOString();
      mem.set(h, r);
      return publicRow(r);
    }
  }
  return null;
}

/** Constant-time compare, for anywhere a secret is checked directly. */
export function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}
