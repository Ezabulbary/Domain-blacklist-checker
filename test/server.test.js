import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';
const { buildServer } = await import('../src/server.js');

// Route-level guarantees that unit tests on the libraries cannot give.

const loginCookie = async (app) => {
  const res = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'admin', password: 'pass-@admin' } });
  return (res.headers['set-cookie'] || '').split(';')[0];
};

test('the zone catalog never exposes scoring weights', async () => {
  const app = buildServer();
  const res = await app.inject({ method: 'GET', url: '/api/zones', headers: { cookie: await loginCookie(app) } });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.ok(body.zones.length > 60);
  for (const z of body.zones) {
    assert.equal('weight' in z, false, `${z.zone} leaks its scoring weight`);
    assert.ok(z.severity, 'severity stays, it is qualitative');
  }
  await app.close();
});

test('a key without the needed scope gets a 403 that names the scope', async () => {
  const app = buildServer();
  const created = await app.inject({
    method: 'POST',
    url: '/api/keys',
    headers: { cookie: await loginCookie(app) },
    payload: { name: 'narrow', scopes: ['auth:read'] },
  });
  const { apiKey } = created.json();
  const res = await app.inject({
    method: 'GET',
    url: '/api/zones',
    headers: { 'x-api-key': apiKey },
  });
  assert.equal(res.statusCode, 403);
  assert.equal(res.json().required, 'zones:read');
  await app.close();
});
