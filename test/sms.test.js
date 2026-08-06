import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderSms, measure, smsTier } from '../src/notify/sms.js';

const base = { brand: 'Acme', url: 'https://acme.io/r/8F3KQ2' };

test('every template fits in a single GSM-7 segment', () => {
  const cases = [
    { ...base, kind: 'listed', domain: 'example.com', zone: 'zen.spamhaus.org' },
    { ...base, kind: 'listed', domain: 'example.com', zone: 'zen.spamhaus.org', extra: 2 },
    { ...base, kind: 'listed', domain: 'example.com', zone: 'b.barracudacentral.org' },
    { ...base, kind: 'listed', domain: 'example.com', zone: 'bl.mailspike.net' },
    { ...base, kind: 'cleared', domain: 'example.com', zone: 'zen.spamhaus.org' },
    { ...base, kind: 'reminder', domain: 'example.com', zone: 'zen.spamhaus.org', days: 7 },
    { ...base, kind: 'multi', domains: 4, urgent: 1 },
    { ...base, kind: 'digest', checked: 12, listings: 2 },
  ];
  for (const c of cases) {
    const r = renderSms(c);
    assert.equal(r.gsm, true, `${c.kind} must be GSM-7: ${r.text}`);
    assert.equal(r.segments, 1, `${c.kind} is ${r.length} chars, over one segment: ${r.text}`);
  }
});

test('a very long domain is shortened instead of spilling into a second segment', () => {
  const long = 'a-really-quite-extraordinarily-long-client-domain-name-here.example.co.uk';
  const r = renderSms({ ...base, kind: 'listed', domain: long, zone: 'zen.spamhaus.org' });
  assert.equal(r.segments, 1, `still one segment, got ${r.length} chars`);
  assert.match(r.text, /\.\.\./, 'the domain is elided in the middle');
  // Both ends survive, so the client can still recognise which domain it is.
  assert.ok(r.text.includes('a-really'), 'keeps the start of the domain');
  assert.ok(r.text.includes('co.uk'), 'keeps the end of the domain');
});

test('urgent wording only for lists that actually block mail', () => {
  const urgent = renderSms({ ...base, kind: 'listed', domain: 'example.com', zone: 'zen.spamhaus.org' });
  assert.match(urgent.text, /URGENT/);
  assert.match(urgent.text, /being blocked right now/);

  const normal = renderSms({ ...base, kind: 'listed', domain: 'example.com', zone: 'truncate.gbudb.net' });
  assert.doesNotMatch(normal.text, /URGENT/);
  assert.match(normal.text, /Some mail may be rejected/);
});

test('collateral-damage lists never earn an SMS', () => {
  for (const zone of ['dnsbl-3.uceprotect.net', 'dnsbl-2.uceprotect.net', 'rhsbl.zapbl.net', 'tor.dan.me.uk']) {
    assert.equal(smsTier(zone), 'none', `${zone} must not text the client`);
  }
  assert.equal(smsTier('zen.spamhaus.org'), 'urgent');
  assert.equal(smsTier('b.barracudacentral.org'), 'urgent');
  assert.equal(smsTier('bl.mailspike.net'), 'normal');
  // A live but minor list falls through to the daily digest.
  assert.equal(smsTier('psbl.surriel.com'), 'digest');
  // A dead list is never worth a message.
  assert.equal(smsTier('spam.rbl.msrbl.net'), 'none');
});

test('measure counts GSM-7 extension characters as two', () => {
  assert.equal(measure('abc').length, 3);
  assert.equal(measure('a{b').length, 4, 'a brace costs two characters in GSM-7');
  assert.equal(measure('160 chars of plain ascii').gsm, true);
});

test('a non-GSM character is refused rather than silently tripling cost', () => {
  // A middle dot is not in GSM-7 and would switch the message to UCS-2, cutting
  // the segment size from 160 to 70 for every recipient.
  const bad = measure('Alert · example.com');
  assert.equal(bad.gsm, false);
  assert.throws(
    () => renderSms({ ...base, brand: 'Acme · Mail', kind: 'multi', domains: 2, urgent: 1 }),
    /not GSM-7/,
  );
});
