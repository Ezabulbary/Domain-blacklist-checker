import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkDomain } from '../src/lib/check.js';

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
