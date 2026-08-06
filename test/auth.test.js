import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkAuth, checkSpf, checkDmarc, checkDkim, checkMx, checkPtr, authScore } from '../src/lib/auth.js';

// Fake resolver: map query -> canned answer or an error code.
function fakeResolver(map) {
  const err = (code) => { const e = new Error(code); e.code = code; return e; };
  const get = (kind, name) => {
    const v = map[`${kind}:${name}`];
    if (v === undefined) return Promise.reject(err('ENOTFOUND'));
    if (typeof v === 'string') return Promise.reject(err(v));
    return Promise.resolve(v);
  };
  return {
    resolveTxt: (n) => get('txt', n),
    resolveMx: (n) => get('mx', n),
    resolve4: (n) => get('a', n),
    reverse: (ip) => get('ptr', ip),
  };
}

test('SPF: parses hard-fail policy and lookup count', async () => {
  const r = fakeResolver({ 'txt:x.com': [['v=spf1 include:_spf.google.com include:mailgun.org -all']] });
  const s = await checkSpf('x.com', r);
  assert.equal(s.present, true);
  assert.equal(s.qualifier, '-');
  assert.equal(s.status, 'pass');
  assert.equal(s.lookups, 2);
});

test('SPF: +all is flagged as weak', async () => {
  const r = fakeResolver({ 'txt:x.com': [['v=spf1 +all']] });
  const s = await checkSpf('x.com', r);
  assert.equal(s.status, 'warn');
});

test('SPF: missing record', async () => {
  const s = await checkSpf('x.com', fakeResolver({}));
  assert.equal(s.present, false);
  assert.equal(s.status, 'missing');
});

test('DMARC: parses policy and rua', async () => {
  const r = fakeResolver({ 'txt:_dmarc.x.com': [['v=DMARC1; p=reject; rua=mailto:d@x.com; pct=100']] });
  const d = await checkDmarc('x.com', r);
  assert.equal(d.present, true);
  assert.equal(d.policy, 'reject');
  assert.equal(d.status, 'pass');
  assert.equal(d.rua, 'mailto:d@x.com');
});

test('DMARC: p=none is a warning', async () => {
  const r = fakeResolver({ 'txt:_dmarc.x.com': [['v=DMARC1; p=none']] });
  const d = await checkDmarc('x.com', r);
  assert.equal(d.policy, 'none');
  assert.equal(d.status, 'warn');
});

test('DKIM: finds a published selector', async () => {
  const r = fakeResolver({ 'txt:google._domainkey.x.com': [['v=DKIM1; k=rsa; p=MIGfMA0']] });
  const d = await checkDkim('x.com', ['google', 'selector1'], r);
  assert.equal(d.present, true);
  assert.deepEqual(d.selectors.map((s) => s.selector), ['google']);
});

test('MX: sorted by priority', async () => {
  const r = fakeResolver({ 'mx:x.com': [{ exchange: 'b.mx', priority: 20 }, { exchange: 'a.mx', priority: 10 }] });
  const m = await checkMx('x.com', r);
  assert.deepEqual(m.records.map((x) => x.exchange), ['a.mx', 'b.mx']);
});

test('PTR: forward-confirmed reverse DNS', async () => {
  const r = fakeResolver({ 'ptr:1.2.3.4': ['mail.x.com'], 'a:mail.x.com': ['1.2.3.4'] });
  const p = await checkPtr(['1.2.3.4'], 'x.com', r);
  assert.equal(p.status, 'pass');
  assert.equal(p.records[0].forwardConfirmed, true);
});

test('authScore: full stack scores high, empty scores low', () => {
  const full = authScore({
    spf: { present: true, status: 'pass' },
    dkim: { present: true },
    dmarc: { present: true, policy: 'reject' },
    ptr: { status: 'pass' },
  });
  assert.ok(full >= 95, `expected high, got ${full}`);
  const none = authScore({ spf: { present: false }, dkim: { present: false }, dmarc: { present: false }, ptr: { status: 'warn' } });
  assert.ok(none <= 10, `expected low, got ${none}`);
});

// --- A failed lookup is not an absent record -------------------------------
//
// checkSpf/checkDmarc/checkMx return status 'unknown' when the query failed
// (ETIMEOUT on a large apex TXT set, SERVFAIL, refused). Reporting that as
// "missing" tells a client to publish a record they already have, and is the
// same mistake as calling a domain clean because a blocklist did not answer.

test('a timed-out SPF lookup is unknown, never missing', async () => {
  const boom = async () => { const e = new Error('x'); e.code = 'ETIMEOUT'; throw e; };
  const spf = await checkSpf('example.com', { resolveTxt: boom });
  assert.equal(spf.status, 'unknown');
  assert.equal(spf.present, false);
  assert.equal(spf.error, 'ETIMEOUT');
});

test('checkAuth flags the result as incomplete when a lookup failed', async () => {
  const boom = async () => { const e = new Error('x'); e.code = 'ETIMEOUT'; throw e; };
  const ok = async () => [['v=spf1 -all']];
  const complete = await checkAuth('example.com', {
    resolver: { resolveTxt: ok, resolveMx: async () => [{ exchange: 'mx.example.com', priority: 10 }] },
  });
  assert.equal(complete.complete, true);

  const partial = await checkAuth('example.com', {
    resolver: { resolveTxt: boom, resolveMx: async () => [{ exchange: 'mx.example.com', priority: 10 }] },
  });
  assert.equal(partial.complete, false, 'a failed SPF lookup makes the audit incomplete');
});

test('bulk reports a failed lookup as unknown, not missing', async () => {
  const { checkMany } = await import('../src/lib/bulk.js');
  const boom = async () => { const e = new Error('x'); e.code = 'ETIMEOUT'; throw e; };
  const resolver = {
    resolve4: async () => ['1.2.3.4'],
    resolve6: boom,
    resolveTxt: boom,          // SPF and DMARC both fail
    resolveMx: async () => [{ exchange: 'mx.example.com', priority: 10 }],
    reverse: boom,
  };
  const { results } = await checkMany(['example.com'], {
    resolver, withAuth: true, calibration: false, concurrency: 1,
  });
  const a = results[0].auth;
  assert.equal(a.spf, 'unknown', 'SPF lookup failed, so it is unknown');
  assert.equal(a.dmarc, 'unknown', 'DMARC lookup failed, so it is unknown');
  assert.equal(a.complete, false);
});

test('no recommendation to publish a record we could not read', async () => {
  const { recommend } = await import('../src/lib/recommend.js');
  const failed = { status: 'unknown', present: false, error: 'ETIMEOUT' };
  const recs = recommend({
    auth: { spf: failed, dmarc: failed, dkim: { present: true, status: 'pass', selectors: [] } },
    table: [],
  });
  assert.equal(recs.filter((r) => /No SPF record|No DMARC record/.test(r.title)).length, 0,
    'a failed lookup must not produce a "publish this record" recommendation');
});

// --- The auth score only counts what could actually be checked -------------

test('a failed lookup does not cost points, a missing record does', () => {
  const dkim = { present: true, status: 'pass' };
  const dmarc = { present: true, status: 'pass', policy: 'reject' };
  const ptr = { status: 'pass' };

  const missing = authScore({ spf: { present: false, status: 'missing' }, dkim, dmarc, ptr });
  const failed = authScore({ spf: { present: false, status: 'unknown', error: 'ETIMEOUT' }, dkim, dmarc, ptr });

  assert.equal(missing, 70, 'a genuinely absent SPF record costs its 30 points');
  assert.equal(failed, 100, 'a DNS timeout is not evidence of a missing record');
  assert.notEqual(missing, failed, 'these two must not score the same');
});

test('no PTR to check does not hand out free points', () => {
  // Nothing published at all, and no IPs to check reverse DNS on. This used to
  // score 10 out of a PTR that was never looked at.
  const s = authScore({
    spf: { present: false, status: 'missing' },
    dkim: { present: false, status: 'unknown' },
    dmarc: { present: false, status: 'missing' },
    ptr: null,
  });
  assert.equal(s, 0);
});

test('a domain-only check still reaches 100 when everything passes', () => {
  const s = authScore({
    spf: { present: true, status: 'pass' },
    dkim: { present: true, status: 'pass' },
    dmarc: { present: true, status: 'pass', policy: 'reject' },
    ptr: null,
  });
  assert.equal(s, 100, 'dropping PTR rescales rather than caps the score');
});

test('nothing checkable at all -> null, not zero', () => {
  const unknown = { present: false, status: 'unknown', error: 'ETIMEOUT' };
  assert.equal(authScore({ spf: unknown, dkim: null, dmarc: unknown, ptr: null }), null);
});
