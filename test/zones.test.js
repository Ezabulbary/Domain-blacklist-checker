import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IP_ZONES, DOMAIN_ZONES, ALL_ZONES, CATEGORIES } from '../src/lib/zones.js';
import { queryZone } from '../src/lib/resolve.js';

test('catalog covers the full mxtoolbox-style set (~68 zones)', () => {
  assert.ok(ALL_ZONES.length >= 65, `expected ~68 zones, got ${ALL_ZONES.length}`);
});

test('every zone has required, well-formed fields', () => {
  const seen = new Set();
  for (const z of ALL_ZONES) {
    assert.ok(z.name && typeof z.name === 'string', `name missing on ${z.zone}`);
    assert.match(z.zone, /^[a-z0-9.-]+$/, `bad zone host: ${z.zone}`);
    assert.ok(['ip', 'domain'].includes(z.type), `bad type on ${z.zone}`);
    assert.ok(z.weight >= 0 && z.weight <= 40, `bad weight on ${z.zone}`);
    assert.ok(['critical', 'high', 'medium', 'low'].includes(z.severity), `bad severity on ${z.zone}`);
    assert.ok(['live', 'requiresKey', 'defunct', 'unverified'].includes(z.status), `bad status on ${z.zone}`);
    assert.ok(!seen.has(z.zone), `duplicate zone ${z.zone}`);
    seen.add(z.zone);
  }
});

test('IP_ZONES are type ip, DOMAIN_ZONES are type domain', () => {
  assert.ok(IP_ZONES.every((z) => z.type === 'ip'));
  assert.ok(DOMAIN_ZONES.every((z) => z.type === 'domain'));
});

test('every zone gets a valid category', () => {
  const valid = new Set(['email', 'ip', 'domain', 'spam', 'malware', 'whitelist']);
  for (const z of ALL_ZONES) {
    assert.ok(valid.has(z.category), `bad category "${z.category}" on ${z.zone}`);
  }
  // CATEGORIES drives the UI filter and must include the real ones.
  assert.ok(CATEGORIES.some((c) => c.key === 'all'));
  assert.ok(CATEGORIES.some((c) => c.key === 'domain'));
});

test('a DQS key never leaks into the public zone name', async () => {
  // The key is a secret. It may only appear in queryHost (used to build the DNS
  // name), never in `zone`, which the API and UI expose.
  const KEY = 'testkeytestkeytestkey12345';
  process.env.DBC_DQS_KEY = KEY;
  const mod = await import('../src/lib/zones.js?dqs=1');
  try {
    const zen = mod.ALL_ZONES.find((z) => z.zone === 'zen.spamhaus.org');
    assert.ok(zen, 'ZEN present');
    assert.equal(zen.zone.includes(KEY), false, 'public zone name must not contain the key');
    assert.ok(mod.queryHostOf(zen).includes(KEY), 'the key is used to build the query host');
    assert.match(mod.queryHostOf(zen), /\.zen\.dq\.spamhaus\.net$/);
    for (const z of mod.ALL_ZONES) {
      assert.equal(z.zone.includes(KEY), false, `key leaked into ${z.name}`);
    }
  } finally {
    delete process.env.DBC_DQS_KEY;
  }
});

test('Spamhaus ZEN and DBL are present and critical', () => {
  const zen = ALL_ZONES.find((z) => z.zone === 'zen.spamhaus.org');
  const dbl = ALL_ZONES.find((z) => z.zone === 'dbl.spamhaus.org');
  assert.equal(zen.severity, 'critical');
  assert.equal(dbl.severity, 'critical');
});

// --- queryZone behavior with a fake resolver (no network) ---
const fakeResolver = (impl) => ({ resolve4: impl });

test('queryZone: NXDOMAIN -> not listed, with responseMs', async () => {
  const r = await queryZone('4.3.2.1', { zone: 'z.example', name: 'Z' },
    fakeResolver(async () => { const e = new Error('nf'); e.code = 'ENOTFOUND'; throw e; }));
  assert.equal(r.listed, false);
  assert.ok(typeof r.responseMs === 'number');
});

test('queryZone: 127.0.0.2 -> listed with codes + ttl', async () => {
  const r = await queryZone('4.3.2.1', { zone: 'z.example', name: 'Z' },
    fakeResolver(async () => [{ address: '127.0.0.2', ttl: 300 }]));
  assert.equal(r.listed, true);
  assert.deepEqual(r.codes, ['127.0.0.2']);
  assert.equal(r.ttl, 300);
});

test('queryZone: 127.255.255.x block sentinel -> unknown', async () => {
  for (const sentinel of ['127.255.255.254', '127.255.255.255']) {
    const r = await queryZone('4.3.2.1', { zone: 'z.example', name: 'Z' },
      fakeResolver(async () => [{ address: sentinel, ttl: 60 }]));
    assert.equal(r.listed, null);
    assert.equal(r.error, 'PUBLIC_RESOLVER_BLOCKED');
  }
});

test('queryZone: listedCodes filter treats whitelist answer as not listed', async () => {
  const meta = { zone: 'hostkarma.example', name: 'HK', listedCodes: ['127.0.0.2'] };
  const white = await queryZone('4.3.2.1', meta, fakeResolver(async () => [{ address: '127.0.0.1', ttl: 60 }]));
  assert.equal(white.listed, false, '127.0.0.1 is a whitelist answer');
  const black = await queryZone('4.3.2.1', meta, fakeResolver(async () => [{ address: '127.0.0.2', ttl: 60 }]));
  assert.equal(black.listed, true);
});

test('queryZone: requiresKey hit is untrusted (unknown) unless trustKeyed', async () => {
  const meta = { zone: 'k.example', name: 'K', requiresKey: true };
  const untrusted = await queryZone('4.3.2.1', meta, fakeResolver(async () => [{ address: '127.0.0.2', ttl: 60 }]));
  assert.equal(untrusted.listed, null);
  assert.equal(untrusted.error, 'REQUIRES_KEY');
  const trusted = await queryZone('4.3.2.1', meta, fakeResolver(async () => [{ address: '127.0.0.2', ttl: 60 }]), { trustKeyed: true });
  assert.equal(trusted.listed, true);
});
