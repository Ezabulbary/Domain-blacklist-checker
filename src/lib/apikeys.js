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
});

/**
 * Create a key.
 *
 * @param {object} opts
 *   name    what the key is for. Required in spirit, defaulted if absent.
 *   scopes  array of scope strings, or ['all:all']. Defaults to all:all so the
 *           old zero-argument call keeps its meaning.
 *   email   optional, ties the key to a user record.
 * @returns { apiKey, key: {...}, persisted, invalidScopes }
 */
export async function createApiKey({ name, scopes, email } = {}) {
  const apiKey = newKey();
  const keyHash = hash(apiKey);
  const keyPrefix = prefixOf(apiKey);
  const label = (name && String(name).trim()) || 'Unnamed key';

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
      const row = await db.apikeys.createKey({ userId, name: label, keyHash, keyPrefix, scopes: granted });
      return { apiKey, key: publicRow(row), persisted: true, invalidScopes: invalid };
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[keys] database write failed, keeping the key in memory:', e.message);
      const row = { id: ++memId, name: label, prefix: keyPrefix, scopes: granted, createdAt: new Date().toISOString(), revokedAt: null };
      mem.set(keyHash, row);
      return { apiKey, key: publicRow(row), persisted: false, dbFailed: true, invalidScopes: invalid };
    }
  }

  const row = { id: ++memId, name: label, prefix: keyPrefix, scopes: granted, createdAt: new Date().toISOString(), revokedAt: null };
  mem.set(keyHash, row);
  return { apiKey, key: publicRow(row), persisted: false, invalidScopes: invalid };
}

/**
 * Validate a presented key.
 * @returns { scopes, keyId, name, plan, userId? } or null.
 */
export async function validateApiKey(apiKey) {
  if (!apiKey || typeof apiKey !== 'string') return null;
  const keyHash = hash(apiKey);

  if (dbEnabled()) {
    try {
      const row = await db.apikeys.getByHash(keyHash);
      if (row) {
        // Best effort. A slow write here would tax every authenticated request.
        db.apikeys.touch(row.id).catch(() => {});
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
      // the outage: live keys verify, revoked keys are invalid. Only a key
      // with no record anywhere is genuinely unverifiable.
      if (m2) return m2.revokedAt ? null : { scopes: m2.scopes, keyId: m2.id, name: m2.name, plan: 'free' };
      throw new Error('database unreachable, cannot verify this key');
    }
    // DB answered "no such key"; a memory key from an earlier outage may still
    // exist on this instance.
    const m3 = mem.get(keyHash);
    if (m3 && !m3.revokedAt) return { scopes: m3.scopes, keyId: m3.id, name: m3.name, plan: 'free' };
    return null;
  }

  const m = mem.get(keyHash);
  if (!m || m.revokedAt) return null;
  return { scopes: m.scopes, keyId: m.id, name: m.name, plan: 'free' };
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
