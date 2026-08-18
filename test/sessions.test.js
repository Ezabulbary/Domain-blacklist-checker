import { test } from 'node:test';
import assert from 'node:assert/strict';
import { login, getSession, destroySession } from '../src/lib/sessions.js';

process.env.NODE_ENV = 'test';
const { buildServer } = await import('../src/server.js');

// The fixed dashboard accounts. The source stores only password hashes; these
// tests use the real credentials the operator specified.

test('both fixed accounts log in with their role', () => {
  const admin = login('admin', 'pass-@admin');
  assert.equal(admin.role, 'admin');
  assert.match(admin.id, /^[0-9a-f]{32}$/);

  const user = login('user', 'pass@user');
  assert.equal(user.role, 'user');
});

test('wrong credentials fail without saying which half was wrong', () => {
  assert.equal(login('admin', 'wrong'), null);
  assert.equal(login('nobody', 'pass-@admin'), null);
  assert.equal(login('', ''), null);
  assert.equal(login(null, undefined), null);
});

test('a session resolves until destroyed', () => {
  const s = login('admin', 'pass-@admin');
  assert.deepEqual(getSession(s.id), { user: 'admin', role: 'admin' });
  destroySession(s.id);
  assert.equal(getSession(s.id), null);
});

test('garbage session ids never resolve', () => {
  assert.equal(getSession('not-a-session'), null);
  assert.equal(getSession(''), null);
  assert.equal(getSession('../../etc/passwd'), null);
});

// ---- route integration ----

const loginAs = async (app, username, password) => {
  const res = await app.inject({ method: 'POST', url: '/api/login', payload: { username, password } });
  const cookie = (res.headers['set-cookie'] || '').split(';')[0];
  return { res, cookie };
};

test('without a session the API says login required, and static pages still serve', async () => {
  const app = buildServer();
  const zones = await app.inject({ method: 'GET', url: '/api/zones' });
  assert.equal(zones.statusCode, 401);
  assert.equal(zones.json().login, true);

  const page = await app.inject({ method: 'GET', url: '/' });
  assert.equal(page.statusCode, 200, 'the shell serves; the login screen lives inside it');

  const health = await app.inject({ method: 'GET', url: '/api/health' });
  assert.equal(health.statusCode, 200, 'health stays public for monitoring');
  await app.close();
});

test('login sets an HttpOnly cookie and opens the API', async () => {
  const app = buildServer();
  const { res, cookie } = await loginAs(app, 'admin', 'pass-@admin');
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['set-cookie'], /HttpOnly/);
  assert.match(res.headers['set-cookie'], /SameSite=Lax/);

  const zones = await app.inject({ method: 'GET', url: '/api/zones', headers: { cookie } });
  assert.equal(zones.statusCode, 200);

  const meRes = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie } });
  assert.equal(meRes.json().role, 'admin');
  await app.close();
});

test('bad credentials get a generic 401', async () => {
  const app = buildServer();
  const { res } = await loginAs(app, 'admin', 'totally-wrong');
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'wrong username or password');
  await app.close();
});

test('both roles can check domains and create API keys', async () => {
  const app = buildServer();
  const { cookie } = await loginAs(app, 'user', 'pass@user');

  const zones = await app.inject({ method: 'GET', url: '/api/zones', headers: { cookie } });
  assert.equal(zones.statusCode, 200, 'normal features work for the user role');

  const mk = await app.inject({
    method: 'POST', url: '/api/keys', headers: { cookie },
    payload: { name: 'made by the user role', scopes: ['check:read'] },
  });
  assert.equal(mk.statusCode, 200, 'the operator wants both accounts able to create keys');
  assert.match(mk.json().apiKey, /^dbc_/);
  await app.close();
});

test('a session request from a foreign origin is refused on writes', async () => {
  const app = buildServer();
  const { cookie } = await loginAs(app, 'admin', 'pass-@admin');
  const res = await app.inject({
    method: 'POST',
    url: '/api/share',
    headers: { cookie, origin: 'https://evil.example', host: 'localhost:3000' },
    payload: { kind: 'single', data: { domain: 'a.com' } },
  });
  assert.equal(res.statusCode, 403);
  assert.match(res.json().error, /cross-origin/);
  await app.close();
});

test('logout kills the session immediately', async () => {
  const app = buildServer();
  const { cookie } = await loginAs(app, 'admin', 'pass-@admin');
  await app.inject({ method: 'POST', url: '/api/logout', headers: { cookie } });
  const zones = await app.inject({ method: 'GET', url: '/api/zones', headers: { cookie } });
  assert.equal(zones.statusCode, 401);
  await app.close();
});

test('share links stay public: no login needed to view a snapshot', async () => {
  const app = buildServer();
  const { cookie } = await loginAs(app, 'admin', 'pass-@admin');
  const created = await app.inject({
    method: 'POST', url: '/api/share', headers: { cookie },
    payload: { kind: 'single', data: { domain: 'client-report.com' } },
  });
  const { id } = created.json();
  // No cookie at all on the read side, exactly like the client who gets the link.
  const snap = await app.inject({ method: 'GET', url: '/api/share/' + id });
  assert.equal(snap.statusCode, 200);
  assert.equal(snap.json().data.domain, 'client-report.com');
  const page = await app.inject({ method: 'GET', url: '/r/' + id });
  assert.equal(page.statusCode, 200);
  await app.close();
});

test('login attempts are rate limited', async () => {
  const app = buildServer();
  let last;
  for (let i = 0; i < 12; i++) {
    last = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'admin', password: 'nope' + i } });
  }
  assert.equal(last.statusCode, 429, 'brute force runs into the wall');
  await app.close();
});
