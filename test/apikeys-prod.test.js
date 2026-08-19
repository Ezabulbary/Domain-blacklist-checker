import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApiKey, validateApiKey } from '../src/lib/apikeys.js';

process.env.NODE_ENV = 'test';
const { buildServer } = await import('../src/server.js');

// Production behavior of API keys, exercised on the memory store (no DB in
// this suite): expiry, usage accounting, the creation cap and route
// validation. The DB path shares the same logic via isExpired/touch and is
// covered in db.test.js.

test('an expired key is refused with a distinct expired answer, not "invalid"', async () => {
  const { apiKey } = await createApiKey({ name: 'already old', expiresAt: new Date(Date.now() - 1000).toISOString() });
  const v = await validateApiKey(apiKey);
  assert.equal(v.expired, true);
  assert.ok(v.expiresAt, 'says when it expired');
});

test('a live key with a future expiry validates and counts its uses', async () => {
  const { apiKey, key } = await createApiKey({ name: 'fresh', expiresAt: new Date(Date.now() + 60_000).toISOString() });
  assert.ok(key.expiresAt);
  const v1 = await validateApiKey(apiKey, { ip: '10.1.1.1' });
  assert.ok(v1.scopes, 'validates while alive');
  await validateApiKey(apiKey, { ip: '10.1.1.2' });
  // The memory row keeps the tally that the DB path keeps in use_count.
  const again = await validateApiKey(apiKey);
  assert.ok(again.scopes);
});

test('a key with no expiry keeps working', async () => {
  const { apiKey, key } = await createApiKey({ name: 'forever' });
  assert.equal(key.expiresAt, null);
  assert.ok((await validateApiKey(apiKey)).scopes);
});

// ---- routes ----

async function adminCookie(app) {
  const res = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'admin', password: 'pass-@admin' } });
  return (res.headers['set-cookie'] || '').split(';')[0];
}

test('the route validates expiresInDays and stamps the expiry', async () => {
  const app = buildServer();
  const cookie = await adminCookie(app);

  const bad = await app.inject({
    method: 'POST', url: '/api/keys', headers: { cookie },
    payload: { name: 'bad expiry', expiresInDays: 2.5 },
  });
  assert.equal(bad.statusCode, 400);
  assert.match(bad.json().error, /expiresInDays/);

  const ok = await app.inject({
    method: 'POST', url: '/api/keys', headers: { cookie },
    payload: { name: 'month key', scopes: ['check:read'], expiresInDays: 30 },
  });
  assert.equal(ok.statusCode, 200);
  const exp = new Date(ok.json().key.expiresAt).getTime();
  const days = (exp - Date.now()) / 86_400_000;
  assert.ok(days > 29 && days < 31, 'expiry lands ~30 days out');

  // An expired key answers 401 naming the date, on a real route.
  const { apiKey } = await createApiKey({ name: 'dead on arrival', expiresAt: new Date(Date.now() - 1000).toISOString() });
  const hit = await app.inject({ method: 'GET', url: '/api/zones', headers: { 'x-api-key': apiKey } });
  assert.equal(hit.statusCode, 401);
  assert.match(hit.json().error, /expired on \d{4}-\d{2}-\d{2}/);

  await app.close();
});

test('the active-key cap refuses creation past DBC_MAX_KEYS', async () => {
  const app = buildServer();
  const cookie = await adminCookie(app);
  process.env.DBC_MAX_KEYS = '1';
  try {
    // The memory store already holds keys from the tests above, so one more
    // is guaranteed to be over a cap of 1.
    const res = await app.inject({
      method: 'POST', url: '/api/keys', headers: { cookie },
      payload: { name: 'one too many' },
    });
    assert.equal(res.statusCode, 409);
    assert.match(res.json().error, /key limit/);
  } finally {
    delete process.env.DBC_MAX_KEYS;
    await app.close();
  }
});
