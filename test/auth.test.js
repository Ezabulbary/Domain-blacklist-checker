import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSpf, checkDmarc, checkDkim, checkMx, checkPtr, authScore } from '../src/lib/auth.js';

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
