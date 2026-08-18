import { test } from 'node:test';
import assert from 'node:assert/strict';

// A configured-but-unreachable database (bad DATABASE_URL, network down,
// Supabase project paused) must not take share links down with it. This is the
// exact failure the operator hit: DATABASE_URL pointed at a host that does not
// resolve, and the share button showed a raw "getaddrinfo ENOTFOUND".
//
// DATABASE_URL is set BEFORE the modules load so dbEnabled() is true, and the
// db.shares repository is stubbed to fail like a dead connection would.

process.env.DATABASE_URL = 'postgres://user:pass@host-that-does-not-exist.invalid:5432/db';

const { db } = await import('../src/db/index.js');
const { createShare, getShare } = await import('../src/lib/share.js');

const boom = async () => { const e = new Error('getaddrinfo ENOTFOUND host-that-does-not-exist.invalid'); e.code = 'ENOTFOUND'; throw e; };

test('creating a share survives a dead database by falling back to memory', async () => {
  db.shares = { createShare: boom, getShare: boom, sweepShares: async () => 0 };
  const r = await createShare('single', { domain: 'example.com' });
  assert.match(r.id, /^[0-9a-f]{32}$/);
  assert.equal(r.persisted, false, 'the response must say the link is not persisted');
});

test('a memory-held share is still readable while the database is down', async () => {
  db.shares = { createShare: boom, getShare: boom, sweepShares: async () => 0 };
  const r = await createShare('bulk', { results: [{ domain: 'a.com' }] });
  const snap = await getShare(r.id);
  assert.equal(snap.kind, 'bulk');
  assert.equal(snap.payload.results[0].domain, 'a.com');
});

test('an unknown id during an outage reads as missing, not as a crash', async () => {
  db.shares = { createShare: boom, getShare: boom, sweepShares: async () => 0 };
  assert.equal(await getShare('f'.repeat(32)), null);
});
