import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectProvider } from '../src/lib/provider.js';

test('detects the big mailbox providers from MX suffixes', () => {
  assert.equal(detectProvider(['aspmx.l.google.com', 'alt1.aspmx.l.google.com']).name, 'Google Workspace');
  assert.equal(detectProvider(['example-com.mail.protection.outlook.com']).name, 'Microsoft 365');
  assert.equal(detectProvider(['mx.zoho.com', 'mx2.zoho.com']).name, 'Zoho Mail');
  assert.equal(detectProvider(['mail.protonmail.ch']).name, 'Proton Mail');
  assert.equal(detectProvider(['in1-smtp.messagingengine.com']).name, 'Fastmail');
});

test('a security gateway wins over whoever hides behind it', () => {
  // Mimecast in front of Microsoft: the MX only shows Mimecast, and naming
  // Microsoft would be a guess, so the gateway is the answer.
  assert.equal(detectProvider(['us-smtp-inbound-1.mimecast.com']).name, 'Mimecast (gateway)');
  assert.equal(detectProvider(['mx0a-00000000.pphosted.com']).name, 'Proofpoint (gateway)');
  assert.equal(detectProvider(['d000000a.ess.barracudanetworks.com']).name, 'Barracuda (gateway)');
});

test('no MX means no mail service, not "other"', () => {
  assert.equal(detectProvider([]).key, 'none');
  assert.equal(detectProvider(null).key, 'none');
  assert.match(detectProvider([]).name, /no MX/i);
});

test('an unknown MX is labeled other, with a recognisable tail', () => {
  const p = detectProvider(['mail.some-random-host.co']);
  assert.equal(p.key, 'other');
  assert.ok(p.name.includes('some-random-host.co'), p.name);
});

test('matching is suffix-anchored, so lookalike domains do not match', () => {
  // evil-google.com must not read as Google; only *.google.com may.
  assert.equal(detectProvider(['mx.evil-google.com']).key, 'other');
  assert.equal(detectProvider(['mx.google.com.attacker.net']).key, 'other');
});

test('case and trailing dots do not matter', () => {
  assert.equal(detectProvider(['ASPMX.L.GOOGLE.COM.']).name, 'Google Workspace');
});
