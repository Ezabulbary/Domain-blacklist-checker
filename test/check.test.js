import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkDomain } from '../src/lib/check.js';
import { ALL_ZONES } from '../src/lib/zones.js';

const err = (c) => { const e = new Error(c); e.code = c; return e; };

// A resolver whose every lookup fails with a connection error. Simulates a
// machine whose DNS is unreachable (port 53 blocked / no system resolver).
const brokenResolver = {
  resolve4: () => Promise.reject(err('ESERVFAIL')),
  resolve6: () => Promise.reject(err('ESERVFAIL')),
  resolveMx: () => Promise.reject(err('ESERVFAIL')),
  resolveTxt: () => Promise.reject(err('ESERVFAIL')),
  reverse: () => Promise.reject(err('ESERVFAIL')),
};

test('sets dnsError when the resolver cannot reach a DNS server', async () => {
  const r = await checkDomain('github.com', { resolver: brokenResolver, calibration: false, overallTimeoutMs: 2000 });
  assert.equal(r.ok, true);
  assert.equal(r.resolvesTo.length, 0);
  assert.equal(r.dnsError, true);
});

// One A record; every DNSBL zone query answers a clean NXDOMAIN.
// resolve4 returns strings normally, {address,ttl} objects when ttl:true.
const cleanResolver = {
  resolve4: (name, opts) => name === 'example.com'
    ? Promise.resolve(opts && opts.ttl ? [{ address: '1.2.3.4', ttl: 60 }] : ['1.2.3.4'])
    : Promise.reject(err('ENOTFOUND')),
  resolve6: () => Promise.reject(err('ENOTFOUND')),
  resolveMx: () => Promise.reject(err('ENOTFOUND')),
  resolveTxt: () => Promise.reject(err('ENOTFOUND')),
  reverse: () => Promise.reject(err('ENOTFOUND')),
};

test('without calibration, defunct / key-only lists are skipped (not timeouts)', async () => {
  delete process.env.DBC_TRUST_KEYED;
  const r = await checkDomain('example.com', {
    resolver: cleanResolver, calibration: false, retries: 0, overallTimeoutMs: 4000,
  });
  const expectedSkipped = ALL_ZONES.filter((z) => z.status === 'defunct' || z.status === 'requiresKey').length;
  assert.equal(r.timeoutCount, 0, 'no timeouts when every queried list answers');
  assert.equal(r.skippedCount, expectedSkipped, 'defunct + key-only zones are skipped');
  assert.ok(r.skippedCount > 0);
});

test('calibration decides what is queried: untrusted lists are skipped, not scored', async () => {
  // Pretend only one zone is trustworthy; everything else must be skipped.
  const trustedZone = ALL_ZONES[0].zone;
  const zones = {};
  for (const z of ALL_ZONES) {
    zones[z.zone] = z.zone === trustedZone
      ? { verdict: 'verified', reason: 'test entry listed, control clean' }
      : { verdict: 'always-positive', reason: 'answers listed for everything' };
  }
  const r = await checkDomain('example.com', {
    resolver: cleanResolver, calibration: { at: Date.now(), zones }, retries: 0, overallTimeoutMs: 4000,
  });
  assert.equal(r.trustedZones, 1, 'only the calibrated-trusted zone is queried');
  assert.equal(r.skippedCount, ALL_ZONES.length - 1, 'every untrusted zone is skipped');
  assert.equal(r.listedCount, 0, 'untrusted zones can never contribute a listing');
  // The skip reason comes from calibration, so the UI can explain why.
  const skipped = r.table.find((x) => x.state === 'skipped');
  assert.match(skipped.reason, /answers listed/);
});

test('does not set dnsError for a genuinely record-less (NXDOMAIN) domain', async () => {
  const nx = {
    resolve4: () => Promise.reject(err('ENOTFOUND')),
    resolve6: () => Promise.reject(err('ENOTFOUND')),
    resolveMx: () => Promise.reject(err('ENOTFOUND')),
    resolveTxt: () => Promise.reject(err('ENOTFOUND')),
    reverse: () => Promise.reject(err('ENOTFOUND')),
  };
  const r = await checkDomain('example.com', { resolver: nx, calibration: false, overallTimeoutMs: 2000 });
  assert.equal(r.dnsError, false, 'clean NXDOMAIN is not a resolver failure');
});

test('a SURBL multi hit decodes its bitmask into the listed reason', async () => {
  // Answer 127.0.0.72 (8 phishing + 64 abuse) for the SURBL query only;
  // everything else is clean.
  const resolver = {
    resolve4: (name, opts) => {
      if (name === 'example.com') {
        return Promise.resolve(opts && opts.ttl ? [{ address: '1.2.3.4', ttl: 60 }] : ['1.2.3.4']);
      }
      if (name.endsWith('.multi.surbl.org')) {
        return Promise.resolve(opts && opts.ttl ? [{ address: '127.0.0.72', ttl: 60 }] : ['127.0.0.72']);
      }
      return Promise.reject(err('ENOTFOUND'));
    },
    resolve6: () => Promise.reject(err('ENOTFOUND')),
    resolveMx: () => Promise.reject(err('ENOTFOUND')),
    resolveTxt: () => Promise.reject(err('ENOTFOUND')),
    reverse: () => Promise.reject(err('ENOTFOUND')),
  };
  const r = await checkDomain('example.com', {
    resolver, calibration: false, retries: 0, overallTimeoutMs: 4000,
  });
  const row = r.table.find((x) => x.zone === 'multi.surbl.org');
  assert.equal(row.state, 'listed');
  assert.match(row.reason, /phishing dataset/);
  assert.match(row.reason, /ABUSE: spam\/abuse dataset/);
});
