import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeScopes, hasScope, scopeFor, SCOPES, SCOPE_KEYS, ALL_SCOPE, ROUTE_SCOPES } from '../src/lib/scopes.js';
import { createApiKey, validateApiKey, listApiKeys, revokeApiKey } from '../src/lib/apikeys.js';

test('all:all grants everything, including a scope it does not list', () => {
  assert.equal(hasScope([ALL_SCOPE], 'check:read'), true);
  assert.equal(hasScope([ALL_SCOPE], 'bulk:write'), true);
  // A scope added in a future version must still be covered.
  assert.equal(hasScope([ALL_SCOPE], 'something:new'), true);
});

test('a narrow key is refused anything outside its scopes', () => {
  const granted = ['check:read'];
  assert.equal(hasScope(granted, 'check:read'), true);
  assert.equal(hasScope(granted, 'bulk:write'), false, 'bulk is deliberately separate from a single check');
  assert.equal(hasScope(granted, 'keys:write'), false);
});

test('all:all collapses the selection instead of sitting alongside it', () => {
  // Keeping both would read as "limited to check:read", which is the opposite
  // of what all:all means.
  const { scopes } = normalizeScopes(['check:read', ALL_SCOPE, 'auth:read']);
  assert.deepEqual(scopes, [ALL_SCOPE]);
});

test('normalizeScopes reports unknown scopes rather than dropping them', () => {
  const { scopes, invalid } = normalizeScopes(['check:read', 'nope:read', 'auth:read']);
  assert.deepEqual(scopes, ['check:read', 'auth:read']);
  assert.deepEqual(invalid, ['nope:read']);
});

test('normalizeScopes accepts a string, trims, lowercases and de-dupes', () => {
  const { scopes } = normalizeScopes(' CHECK:read, check:read  auth:read ');
  assert.deepEqual(scopes, ['check:read', 'auth:read']);
});

test('every catalog scope is actually used by a route, and vice versa', () => {
  const routeScopes = new Set(Object.values(ROUTE_SCOPES));
  for (const key of SCOPE_KEYS) {
    assert.ok(routeScopes.has(key), `scope ${key} is offered but no route requires it`);
  }
  for (const s of routeScopes) {
    assert.ok(SCOPE_KEYS.includes(s), `route requires ${s}, which the create form never offers`);
  }
});

test('every scope in the catalog documents the endpoints it covers', () => {
  for (const s of SCOPES) {
    assert.ok(s.label && s.detail, `${s.key} needs a label and a description`);
    assert.ok(s.endpoints?.length, `${s.key} should say which endpoints it covers`);
    for (const ep of s.endpoints) {
      // Every advertised endpoint maps back to this scope, except the key
      // routes, where DELETE takes a path parameter.
      if (ROUTE_SCOPES[ep]) assert.equal(ROUTE_SCOPES[ep], s.key, `${ep} advertised under the wrong scope`);
    }
  }
});

test('scopeFor resolves method and path', () => {
  assert.equal(scopeFor('GET', '/api/check'), 'check:read');
  assert.equal(scopeFor('post', '/api/check/bulk'), 'bulk:write');
  assert.equal(scopeFor('GET', '/api/health'), null, 'health needs no scope');
});

// --- key lifecycle, on the in-memory store (no DATABASE_URL in tests) -------

test('a created key validates and carries exactly the scopes asked for', async () => {
  const r = await createApiKey({ name: 'reporting script', scopes: ['check:read', 'auth:read'] });
  assert.match(r.apiKey, /^dbc_[0-9a-f]{48}$/);
  assert.deepEqual(r.key.scopes, ['check:read', 'auth:read']);
  assert.equal(r.key.name, 'reporting script');

  const v = await validateApiKey(r.apiKey);
  assert.deepEqual(v.scopes, ['check:read', 'auth:read']);
  assert.equal(hasScope(v.scopes, 'check:read'), true);
  assert.equal(hasScope(v.scopes, 'bulk:write'), false);
});

test('the key itself is never handed back in a listing, only its prefix', async () => {
  const r = await createApiKey({ name: 'listed key', scopes: [ALL_SCOPE] });
  const keys = await listApiKeys();
  const row = keys.find((k) => k.id === r.key.id);
  assert.ok(row, 'the key appears in the listing');
  assert.equal(row.prefix, r.apiKey.slice(0, 12));
  assert.equal(JSON.stringify(row).includes(r.apiKey), false, 'the full key must never appear in a listing');
});

test('a revoked key stops validating', async () => {
  const r = await createApiKey({ name: 'temporary', scopes: ['zones:read'] });
  assert.ok(await validateApiKey(r.apiKey));
  await revokeApiKey(r.key.id);
  assert.equal(await validateApiKey(r.apiKey), null);
});

test('an empty scope selection defaults rather than creating a dead key', async () => {
  const r = await createApiKey({ name: 'no scopes given', scopes: [] });
  assert.deepEqual(r.key.scopes, [ALL_SCOPE], 'a key that can call nothing is never what was meant');
});

test('a garbage key does not validate', async () => {
  assert.equal(await validateApiKey('dbc_not_a_real_key'), null);
  assert.equal(await validateApiKey(''), null);
  assert.equal(await validateApiKey(null), null);
  assert.equal(await validateApiKey({ toString: () => 'x' }), null, 'a non-string must not be coerced');
});
