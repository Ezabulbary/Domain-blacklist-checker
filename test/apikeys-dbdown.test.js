import { test } from 'node:test';
import assert from 'node:assert/strict';

// The operator's exact failure: DATABASE_URL set to an unresolvable host, so
// creating a key answered a raw "getaddrinfo ENOTFOUND" and using any key
// answered 503. Keys must degrade like share links do: issue into the bounded
// memory store, keep verifying from it during the outage, and say clearly when
// a key cannot be checked either way.

process.env.DATABASE_URL = 'postgres://user:pass@host-that-does-not-exist.invalid:5432/db';

const { db } = await import('../src/db/index.js');
const { createApiKey, validateApiKey, listApiKeys, revokeApiKey } = await import('../src/lib/apikeys.js');

const boom = async () => { const e = new Error('getaddrinfo ENOTFOUND host-that-does-not-exist.invalid'); e.code = 'ENOTFOUND'; throw e; };
const deadDb = () => {
  db.apikeys = { createKey: boom, getByHash: boom, touch: boom, listKeys: boom, revokeKey: boom };
  db.users = { upsertUserByEmail: boom, getUserByApiKey: boom };
};

test('creating a key survives a dead database by falling back to memory', async () => {
  deadDb();
  const r = await createApiKey({ name: 'made during outage', scopes: ['check:read'] });
  assert.match(r.apiKey, /^dbc_[0-9a-f]{48}$/);
  assert.equal(r.persisted, false);
  assert.equal(r.dbFailed, true, 'the response must say the database failed, not stay silent');
});

test('a memory key keeps verifying while the database is down', async () => {
  deadDb();
  const r = await createApiKey({ name: 'outage key', scopes: ['auth:read'] });
  const v = await validateApiKey(r.apiKey);
  assert.deepEqual(v.scopes, ['auth:read']);
});

test('a key that cannot be checked either way is an error, not a guess', async () => {
  deadDb();
  // Not in memory, and the DB cannot answer: calling it valid would grant
  // access on faith, calling it invalid would 401 a legitimate key.
  await assert.rejects(
    () => validateApiKey('dbc_' + 'ab'.repeat(24)),
    /database unreachable/,
  );
});

test('listing and revoking fall back to the memory store', async () => {
  deadDb();
  const r = await createApiKey({ name: 'to revoke', scopes: ['zones:read'] });
  const listed = await listApiKeys();
  assert.ok(listed.some((k) => k.id === r.key.id), 'the memory key appears in the outage listing');
  const revoked = await revokeApiKey(r.key.id);
  assert.ok(revoked.revokedAt);
  assert.equal(await validateApiKey(r.apiKey), null, 'a revoked memory key stops working');
});
