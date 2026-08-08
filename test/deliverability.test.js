import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deliverabilityScore, reputationReport, REPUTATION_SYSTEMS } from '../src/lib/deliverability.js';
import { riskScore } from '../src/lib/analyze.js';

// The blend: blocklists carry most of the score, receiver-side reputation the
// next share, DNS authentication the smallest. Components that cannot be
// measured drop out of the denominator entirely.

test('with no reputation feed, blocklists dominate and auth is the small share', () => {
  // blocklists 100, auth 0 -> auth's share of the measurable pool is small,
  // so the score stays high but clearly dented.
  const r = deliverabilityScore({ blocklist: 100, auth: 0 });
  assert.equal(r.score, 80);
  // and the reverse: perfect auth cannot rescue a zeroed blocklist score.
  const r2 = deliverabilityScore({ blocklist: 0, auth: 100 });
  assert.equal(r2.score, 20);
});

test('reputation joins the blend only when actually measured', () => {
  const without = deliverabilityScore({ blocklist: 80, auth: 80 });
  assert.equal(without.score, 80);
  assert.equal(without.components.reputation.measured, false);
  assert.equal(without.components.reputation.score, null);

  const withRep = deliverabilityScore({ blocklist: 80, auth: 80, reputation: 20 });
  assert.ok(withRep.score < without.score, 'a bad reputation must pull the score down once connected');
  assert.equal(withRep.components.reputation.measured, true);
});

test('nothing measurable -> no score, not a flattering number', () => {
  const r = deliverabilityScore({});
  assert.equal(r.score, null);
  assert.equal(r.standing, 'not measured');
});

test('components carry scores and measured flags, never weights', () => {
  const r = deliverabilityScore({ blocklist: 90, auth: 50 });
  for (const c of Object.values(r.components)) {
    assert.deepEqual(Object.keys(c).sort(), ['measured', 'score'],
      'a component must not leak its weight or share');
  }
});

test('riskScore keeps its shape for existing callers', () => {
  const good = riskScore({ bl: { score: 100 }, auth: { score: 100 } });
  assert.equal(good.score, 100);
  assert.equal(good.standing, 'good standing');
  const bad = riskScore({ bl: { score: 30 }, auth: { score: 20 } });
  assert.equal(bad.standing, 'poor');
});

test('reputation report fills lookup URLs and never claims to be connected', () => {
  const rows = reputationReport({ ip: '1.2.3.4', domain: 'example.com' });
  assert.equal(rows.length, REPUTATION_SYSTEMS.length);
  for (const r of rows) {
    assert.equal(r.status, 'manual');
    assert.match(r.url, /^https:\/\//);
    assert.ok(r.gates && r.means, `${r.key} explains who it gates and what access it needs`);
    assert.equal('weight' in r, false);
  }
  const talos = rows.find((r) => r.key === 'talos');
  assert.ok(talos.url.includes('1.2.3.4'), 'Talos lookup is prefilled with the IP');
});

test('reputation report survives a subject with no IP', () => {
  const rows = reputationReport({ ip: null, domain: 'example.com' });
  const talos = rows.find((r) => r.key === 'talos');
  assert.ok(talos.url.includes('example.com'), 'Talos falls back to the domain');
});
