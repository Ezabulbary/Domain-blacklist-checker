import { test } from 'node:test';
import assert from 'node:assert/strict';
import { beat, markBye, listVisitors, isOnline, parseUserAgent, newVisitorId, isVisitorId, clearVisitors } from '../src/lib/visitors.js';

process.env.NODE_ENV = 'test';
const { buildServer } = await import('../src/server.js');

const CHROME_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const SAFARI_IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (Version/17.5 Mobile/15E148 Safari/604.1)';

// ---- the store ----

test('a heartbeat creates a visitor that reads as online', () => {
  clearVisitors();
  const vid = newVisitorId();
  assert.ok(isVisitorId(vid));
  beat(vid, { ip: '10.0.0.1', userAgent: CHROME_WIN, client: { timezone: 'Asia/Dhaka', language: 'bn-BD' } });
  const [v] = listVisitors();
  assert.equal(v.id, vid);
  assert.equal(v.online, true);
  assert.equal(v.ip, '10.0.0.1');
  assert.equal(v.browser, 'Chrome 126');
  assert.equal(v.os, 'Windows 10/11');
  assert.equal(v.device, 'Desktop');
  assert.equal(v.timezone, 'Asia/Dhaka');
  assert.equal(v.language, 'bn-BD');
});

test('a goodbye beacon flips a visitor to offline right away', () => {
  clearVisitors();
  const vid = newVisitorId();
  beat(vid, { ip: '10.0.0.2', userAgent: CHROME_WIN });
  assert.equal(listVisitors()[0].online, true);
  markBye(vid);
  assert.equal(listVisitors()[0].online, false);
});

test('silence beyond the online window reads as offline', () => {
  clearVisitors();
  const vid = newVisitorId();
  const r = beat(vid, { ip: '10.0.0.3', userAgent: CHROME_WIN });
  assert.equal(isOnline(r), true);
  // Pretend hours have passed instead of sleeping through the real window.
  assert.equal(isOnline(r, Date.now() + 4 * 60 * 60 * 1000), false);
});

test('signing out keeps the name with a signed-out marker', () => {
  clearVisitors();
  const vid = newVisitorId();
  beat(vid, { ip: '10.0.0.4', userAgent: CHROME_WIN, user: 'admin', role: 'admin' });
  assert.equal(listVisitors()[0].loggedOut, false);
  beat(vid, { ip: '10.0.0.4', userAgent: CHROME_WIN });
  const [v] = listVisitors();
  assert.equal(v.user, 'admin');
  assert.equal(v.loggedOut, true);
});

test('client strings are length-capped, never stored raw', () => {
  clearVisitors();
  const vid = newVisitorId();
  beat(vid, { ip: '10.0.0.5', userAgent: CHROME_WIN, client: { page: 'x'.repeat(5000), referrer: 'y'.repeat(5000) } });
  const [v] = listVisitors();
  assert.ok(v.page.length <= 80);
  assert.ok(v.referrer.length <= 300);
});

test('the user agent reader names common browsers and says Unknown otherwise', () => {
  assert.deepEqual(parseUserAgent(SAFARI_IPHONE), { browser: 'Safari 17', os: 'iOS', device: 'Mobile' });
  const u = parseUserAgent('curl/8.0');
  assert.equal(u.browser, 'Unknown browser');
  assert.equal(u.os, 'Unknown OS');
});

// ---- the routes ----

test('presence is public and hands out a visitor cookie; the list is the admin\'s alone', async () => {
  clearVisitors();
  const app = buildServer();

  // Anyone can announce themselves, no login involved.
  const p = await app.inject({
    method: 'POST', url: '/api/presence',
    headers: { 'content-type': 'application/json', 'user-agent': CHROME_WIN },
    payload: { timezone: 'Asia/Dhaka', screen: '1920x1080' },
  });
  assert.equal(p.statusCode, 200);
  const vidCookie = (p.headers['set-cookie'] || '').split(';')[0];
  assert.match(vidCookie, /^dbc_vid=[a-f0-9]{32}$/);

  // Not logged in: no list.
  const anon = await app.inject({ method: 'GET', url: '/api/visitors' });
  assert.equal(anon.statusCode, 401);

  // The user role: still no list.
  const lu = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'user', password: 'pass@user' } });
  const userCookie = (lu.headers['set-cookie'] || '').split(';')[0];
  const asUser = await app.inject({ method: 'GET', url: '/api/visitors', headers: { cookie: userCookie } });
  assert.equal(asUser.statusCode, 403);

  // The admin sees the guest that beat above, online, with parsed agent data.
  const la = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'admin', password: 'pass-@admin' } });
  const adminCookie = (la.headers['set-cookie'] || '').split(';')[0];
  const list = await app.inject({ method: 'GET', url: '/api/visitors', headers: { cookie: adminCookie } });
  assert.equal(list.statusCode, 200);
  const j = list.json();
  assert.equal(j.ok, true);
  const guest = j.visitors.find((v) => v.screen === '1920x1080');
  assert.ok(guest, 'the anonymous visitor is listed');
  assert.equal(guest.online, true);
  assert.equal(guest.browser, 'Chrome 126');
  assert.equal(guest.user, undefined);

  await app.close();
});

test('a logged-in heartbeat carries the account, and bye flips it offline', async () => {
  clearVisitors();
  const app = buildServer();
  const la = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'admin', password: 'pass-@admin' } });
  const adminCookie = (la.headers['set-cookie'] || '').split(';')[0];

  const p = await app.inject({
    method: 'POST', url: '/api/presence',
    headers: { 'content-type': 'application/json', 'user-agent': CHROME_WIN, cookie: adminCookie },
    payload: { page: 'Analyze' },
  });
  const vidCookie = (p.headers['set-cookie'] || '').split(';')[0];

  let list = (await app.inject({ method: 'GET', url: '/api/visitors', headers: { cookie: adminCookie } })).json();
  let mine = list.visitors.find((v) => v.user === 'admin');
  assert.ok(mine, 'the signed-in visitor carries the account name');
  assert.equal(mine.online, true);

  // sendBeacon posts arrive as text/plain: still parsed, still honored.
  await app.inject({
    method: 'POST', url: '/api/presence',
    headers: { 'content-type': 'text/plain', cookie: adminCookie + '; ' + vidCookie },
    payload: JSON.stringify({ bye: true }),
  });
  list = (await app.inject({ method: 'GET', url: '/api/visitors', headers: { cookie: adminCookie } })).json();
  mine = list.visitors.find((v) => v.user === 'admin');
  assert.equal(mine.online, false);

  await app.close();
});
