import { randomBytes } from 'node:crypto';
import { dbEnabled } from '../db/pool.js';
import { db } from '../db/index.js';

// API keys are OPTIONAL by default — the API works without one. A key lets you
// authenticate (for higher rate limits / attribution), and the server can be
// told to require one with DBC_REQUIRE_KEY=true.
//
// When a database is configured, keys live in the `users` table (persistent).
// Without a database we keep them in memory so the feature still works for a
// demo — but those keys are lost on restart.

const mem = new Map(); // apiKey -> { plan, createdAt }

export const newKey = () => 'dbc_' + randomBytes(24).toString('hex');

/** Create and store a new API key. Optional email ties it to a user record. */
export async function createApiKey({ email } = {}) {
  const apiKey = newKey();
  if (dbEnabled()) {
    const mail = email && String(email).trim() ? String(email).trim() : `key_${apiKey.slice(4, 16)}@local.key`;
    try {
      const u = await db.users.createUser({ email: mail, apiKey });
      return { apiKey: u.api_key, plan: u.plan, persisted: true };
    } catch {
      // Email already exists — rotate that user's key instead.
      const existing = await db.users.getUserByEmail(mail);
      if (existing) {
        const r = await db.users.rotateApiKey(existing.id, apiKey);
        return { apiKey: r.api_key, plan: r.plan, persisted: true };
      }
      throw new Error('could not create API key');
    }
  }
  mem.set(apiKey, { plan: 'free', createdAt: Date.now() });
  return { apiKey, plan: 'free', persisted: false };
}

/** Validate a key. Returns { plan, ... } if valid, else null. */
export async function validateApiKey(apiKey) {
  if (!apiKey) return null;
  if (dbEnabled()) {
    const u = await db.users.getUserByApiKey(apiKey);
    return u ? { plan: u.plan, userId: u.id, email: u.email } : null;
  }
  const m = mem.get(apiKey);
  return m ? { plan: m.plan } : null;
}
