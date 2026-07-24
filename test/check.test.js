import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkDomain } from '../src/lib/check.js';
import { ALL_ZONES } from '../src/lib/zones.js';

const err = (c) => { const e = new Error(c); e.code = c; return e; };

// A resolver whose every lookup fails with a connection error — simulates a
// machine whose DNS is unreachable (port 53 blocked / no system resolver).
const brokenResolver = {
  resolve4: () => Promise.reject(err('ESERVFAIL')),
  resolve6: () => Promise.reject(err('ESERVFAIL')),
  resolveMx: () => Promise.reject(err('ESERVFAIL')),
  resolveTxt: () => Promise.reject(err('ESERVFAIL')),
  reverse: () => Promise.reject(err('ESERVFAIL')),
};

test('sets dnsError when the resolver cannot reach a DNS server', async () => {
  const r = await checkDomain('github.com', { resolver: brokenResolver, overallTimeoutMs: 2000 });
  assert.equal(r.ok, true);
  assert.equal(r.resolvesTo.length, 0);
  assert.equal(r.dnsError, true);
});

test('defunct / key-only lists are skipped (not counted as timeouts)', async () => {
  delete process.env.DBC_TRUST_KEYED;
  const err = (c) => { const e = new Error(c); e.code = c; return e; };
  const clean = {
    // The domain has one A record; every DNSBL zone query answers clean NXDOMAIN.
    // resolve4 returns strings normally, {address,ttl} objects when ttl:true.
    resolve4: (name, opts) => name === 'example.com'
      ? Promise.resolve(opts && opts.ttl ? [{ address: '1.2.3.4', ttl: 60 }] : ['1.2.3.4'])
      : Promise.reject(err('ENOTFOUND')),
    resolve6: () => Promise.reject(err('ENOTFOUND')),
    resolveMx: () => Promise.reject(err('ENOTFOUND')),
    resolveTxt: () => Promise.reject(err('ENOTFOUND')),
    reverse: () => Promise.reject(err('ENOTFOUND')),
  };
  const r = await checkDomain('example.com', { resolver: clean, retries: 0, overallTimeoutMs: 4000 });
  const expectedSkipped = ALL_ZONES.filter((z) => z.status === 'defunct' || z.status === 'requiresKey').length;
  assert.equal(r.timeoutCount, 0, 'no timeouts when every queried list answers');
  assert.equal(r.skippedCount, expectedSkipped, 'defunct + key-only zones are skipped');
  assert.ok(r.skippedCount > 0);
});

test('does not set dnsError for a genuinely record-less (NXDOMAIN) domain', async () => {
  const nx = {
    resolve4: () => Promise.reject(err('ENOTFOUND')),
    resolve6: () => Promise.reject(err('ENOTFOUND')),
    resolveMx: () => Promise.reject(err('ENOTFOUND')),
    resolveTxt: () => Promise.reject(err('ENOTFOUND')),
    reverse: () => Promise.reject(err('ENOTFOUND')),
  };
  const r = await checkDomain('example.com', { resolver: nx, overallTimeoutMs: 2000 });
  assert.equal(r.dnsError, false, 'clean NXDOMAIN is not a resolver failure');
});
