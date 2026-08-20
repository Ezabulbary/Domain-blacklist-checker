import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createShare, getShare, MAX_BYTES } from '../src/lib/share.js';

process.env.NODE_ENV = 'test';
const { buildServer } = await import('../src/server.js');

// These run against the in-memory store (no DATABASE_URL under test); the DB
// path uses the same interface through db.shares.

test('a snapshot round-trips under a random id', async () => {
  const r = await createShare('single', { domain: 'example.com', riskScore: 97 });
  assert.match(r.id, /^[0-9a-f]{32}$/, 'the id is 128 random bits of hex');
  const snap = await getShare(r.id);
  assert.equal(snap.kind, 'single');
  assert.equal(snap.payload.domain, 'example.com');
});

test('a bad id shape is rejected before any lookup', async () => {
  assert.equal(await getShare('../../etc/passwd'), null);
  assert.equal(await getShare('short'), null);
  assert.equal(await getShare(''), null);
});

test('kind and payload are validated', async () => {
  await assert.rejects(() => createShare('weird', {}), /kind/);
  await assert.rejects(() => createShare('single', 'not an object'), /object/);
  await assert.rejects(() => createShare('single', [1, 2]), /object/);
});

test('an oversized snapshot is refused with the limit named', async () => {
  const big = { blob: 'x'.repeat(MAX_BYTES + 1024) };
  await assert.rejects(() => createShare('bulk', big), /too large/);
});

test('the share routes work end to end', async () => {
  const app = buildServer();
  const loginRes = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'admin', password: 'pass-@admin' } });
  const cookie = (loginRes.headers['set-cookie'] || '').split(';')[0];
  const created = await app.inject({
    method: 'POST',
    url: '/api/share',
    headers: { cookie },
    payload: { kind: 'bulk', data: { results: [{ ok: true, domain: 'a.com', verdict: 'clean' }] } },
  });
  assert.equal(created.statusCode, 200);
  const { id, url } = created.json();
  assert.equal(url, '/r/' + id);

  const fetched = await app.inject({ method: 'GET', url: '/api/share/' + id });
  assert.equal(fetched.statusCode, 200);
  assert.equal(fetched.json().data.results[0].domain, 'a.com');

  // The share page serves the app shell for any well-formed id.
  const page = await app.inject({ method: 'GET', url: '/r/' + id });
  assert.equal(page.statusCode, 200);
  assert.match(page.headers['content-type'], /text\/html/);

  const missing = await app.inject({ method: 'GET', url: '/api/share/' + 'f'.repeat(32) });
  assert.equal(missing.statusCode, 404);
  await app.close();
});

test('the create response carries a relative url, so the link follows the serving domain', async () => {
  const app = buildServer();
  try {
    const loginRes = await app.inject({ method: 'POST', url: '/api/login', payload: { username: 'admin', password: 'pass-@admin' } });
    const cookie = (loginRes.headers['set-cookie'] || '').split(';')[0];
    const created = await app.inject({
      method: 'POST', url: '/api/share', headers: { cookie },
      payload: { kind: 'single', data: { domain: 'example.com' } },
    });
    const j = created.json();
    assert.equal(j.ok, true);
    assert.match(j.url, /^\/r\/[0-9a-f]{32}$/, 'relative, never a hardcoded host');
    assert.equal(j.shareUrl, undefined, 'no absolute override exists any more');
  } finally { await app.close(); }
});

test('the share page carries a <base> naming this server, host header sanitized', async () => {
  const app = buildServer();
  try {
    const ok = await app.inject({
      method: 'GET', url: '/r/' + 'a'.repeat(32),
      headers: { host: 'blacklist.deliverlymail.com', 'x-forwarded-proto': 'https' },
    });
    assert.equal(ok.statusCode, 200);
    assert.match(ok.body, /<head><base href="https:\/\/blacklist\.deliverlymail\.com\/">/);

    // A hostile Host header is never reflected into the page.
    const evil = await app.inject({
      method: 'GET', url: '/r/' + 'a'.repeat(32),
      headers: { host: 'x"><script>alert(1)</script>' },
    });
    assert.equal(evil.statusCode, 200);
    assert.ok(!evil.body.includes('<base'), 'no base tag for a malformed host');
    assert.ok(!evil.body.includes('alert(1)'), 'nothing reflected');
  } finally { await app.close(); }
});

test('the snapshot endpoint allows cross-origin reads for proxied share pages', async () => {
  const app = buildServer();
  try {
    const r = await createShare('single', { domain: 'example.com' });
    const res = await app.inject({ method: 'GET', url: '/api/share/' + r.id });
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['access-control-allow-origin'], '*');
  } finally { await app.close(); }
});
