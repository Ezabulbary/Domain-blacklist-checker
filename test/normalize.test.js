import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDomain } from '../src/lib/normalize.js';

test('strips protocol, www, path and lowercases', () => {
  const r = normalizeDomain('https://www.EXAMPLE.com/path?q=1');
  assert.equal(r.isValid, true);
  assert.equal(r.domain, 'example.com');
});

test('reduces subdomain to registrable domain', () => {
  const r = normalizeDomain('mail.foo.example.co.uk');
  assert.equal(r.domain, 'example.co.uk');
});

test('strips credentials and port', () => {
  const r = normalizeDomain('http://user:pass@sub.example.org:8080/x');
  assert.equal(r.domain, 'example.org');
});

test('punycodes IDN input', () => {
  const r = normalizeDomain('bücher.de');
  assert.equal(r.isValid, true);
  assert.equal(r.domain, 'xn--bcher-kva.de');
});

test('accepts a bare IPv4 literal as its own subject', () => {
  const r = normalizeDomain('8.8.8.8');
  assert.equal(r.isValid, true);
  assert.equal(r.isIp, true);
  assert.equal(r.domain, '8.8.8.8');
});

test('rejects empty input', () => {
  assert.equal(normalizeDomain('   ').isValid, false);
});

test('rejects invalid TLD', () => {
  assert.equal(normalizeDomain('foo.invalidtldxyz').isValid, false);
});

test('rejects out-of-range IPv4', () => {
  assert.equal(normalizeDomain('999.1.1.1').isValid, false);
});
