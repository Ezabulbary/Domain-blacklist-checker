import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync } from 'node:fs';
import { sslConfig, dbErrorHint } from '../src/db/pool.js';

const PEM = '-----BEGIN CERTIFICATE-----\nMIIFakeFakeFake\n-----END CERTIFICATE-----\n';

test('ssl off when DATABASE_SSL is not true', () => {
  assert.equal(sslConfig({}), undefined);
  assert.equal(sslConfig({ DATABASE_SSL: 'false' }), undefined);
});

test('ssl on verifies by default', () => {
  assert.deepEqual(sslConfig({ DATABASE_SSL: 'true' }), { rejectUnauthorized: true });
});

test('DATABASE_CA accepts the PEM text itself, with escaped newlines unescaped', () => {
  const inline = sslConfig({ DATABASE_SSL: 'true', DATABASE_CA: PEM });
  assert.equal(inline.rejectUnauthorized, true);
  assert.match(inline.ca, /BEGIN CERTIFICATE/);

  const escaped = sslConfig({ DATABASE_SSL: 'true', DATABASE_CA: PEM.replace(/\n/g, '\\n') });
  assert.match(escaped.ca, /-----\nMIIFakeFakeFake\n-----/, 'literal \\n becomes real newlines');
});

test('DATABASE_CA still accepts a file path', () => {
  const p = '/tmp/dbc-test-ca.pem';
  writeFileSync(p, PEM);
  try {
    const s = sslConfig({ DATABASE_SSL: 'true', DATABASE_CA: p });
    assert.match(s.ca, /BEGIN CERTIFICATE/);
  } finally { unlinkSync(p); }
});

test('insecure mode requires the explicit flag', () => {
  const s = sslConfig({ DATABASE_SSL: 'true', DATABASE_SSL_INSECURE: 'true' });
  assert.equal(s.rejectUnauthorized, false);
});

test('the self-signed chain error carries an actionable hint', () => {
  assert.match(dbErrorHint('self-signed certificate in certificate chain'), /DATABASE_CA/);
  assert.match(dbErrorHint('SELF SIGNED CERTIFICATE'), /DATABASE_CA/);
  assert.equal(dbErrorHint('connection refused'), null);
  assert.equal(dbErrorHint(undefined), null);
});
