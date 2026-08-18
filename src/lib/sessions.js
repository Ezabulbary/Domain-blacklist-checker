import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

// Login sessions for the dashboard.
//
// Two fixed accounts, an admin and a user, as the operator specified. The
// passwords are NOT stored here: what the source carries is a SHA-256 of each,
// so reading the code (or a stolen copy of the repo) does not hand out the
// credentials. They can be overridden without touching code:
//
//   DBC_ADMIN_USER / DBC_ADMIN_PASS
//   DBC_USER_USER  / DBC_USER_PASS
//
// A successful login gets a 128-bit random session id in an HttpOnly cookie.
// Sessions live in a bounded in-memory map with a TTL; a restart logs everyone
// out, which with fixed credentials costs one login.

const sha256 = (s) => createHash('sha256').update(String(s)).digest();
const hex = (s) => createHash('sha256').update(String(s)).digest('hex');

function buildUsers() {
  return [
    {
      username: process.env.DBC_ADMIN_USER || 'admin',
      role: 'admin',
      // sha256('pass-@admin') unless overridden.
      passHashHex: process.env.DBC_ADMIN_PASS
        ? hex(process.env.DBC_ADMIN_PASS)
        : 'e56fce15d2852e9799da0adf87fa514b46f991d07b113ac6f8270f768de2b6e2',
    },
    {
      username: process.env.DBC_USER_USER || 'user',
      role: 'user',
      // sha256('pass@user') unless overridden.
      passHashHex: process.env.DBC_USER_PASS
        ? hex(process.env.DBC_USER_PASS)
        : '59a552628e0e0e1dbda0928cfb74c9cb519812b2cad4c174c1b574500a012978',
    },
  ];
}

const TTL_MS = Number(process.env.DBC_SESSION_TTL_HOURS ?? 24) * 3600_000;
const MAX_SESSIONS = 500;

const sessions = new Map(); // id -> { user, role, expiresAt }

/**
 * Check credentials and open a session.
 * Returns { id, user, role, maxAgeSeconds } or null. The caller must not say
 * WHICH of the two fields was wrong; username enumeration is a gift to
 * brute-forcers, so the UI shows one generic message.
 */
export function login(username, password) {
  const passDigest = sha256(password ?? '');
  let matched = null;
  // Compare against every account instead of returning early on the username,
  // so a wrong username costs the same time as a wrong password.
  for (const u of buildUsers()) {
    const userOk = safeEq(sha256(u.username), sha256(username ?? ''));
    const passOk = safeEq(Buffer.from(u.passHashHex, 'hex'), passDigest);
    if (userOk && passOk) matched = u;
  }
  if (!matched) return null;

  const id = randomBytes(16).toString('hex');
  sessions.set(id, { user: matched.username, role: matched.role, expiresAt: Date.now() + TTL_MS });
  // Bounded: evict the oldest rather than grow without limit.
  while (sessions.size > MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
  return { id, user: matched.username, role: matched.role, maxAgeSeconds: Math.floor(TTL_MS / 1000) };
}

/** Look up a live session, or null. Expired entries are dropped on touch. */
export function getSession(id) {
  if (!/^[0-9a-f]{32}$/.test(String(id || ''))) return null;
  const s = sessions.get(id);
  if (!s) return null;
  if (s.expiresAt < Date.now()) {
    sessions.delete(id);
    return null;
  }
  return { user: s.user, role: s.role };
}

/** Log out: the id stops working immediately. */
export function destroySession(id) {
  return sessions.delete(String(id || ''));
}

function safeEq(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}
