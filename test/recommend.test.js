import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recommend } from '../src/lib/recommend.js';
import { analyzeDomain, riskScore } from '../src/lib/analyze.js';

test('recommends delisting for each listing, with the delist link', () => {
  const recs = recommend({
    table: [
      { state: 'listed', name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', subject: '1.2.3.4', severity: 'critical', delist: 'https://check.spamhaus.org/' },
      { state: 'ok', name: 'Other', zone: 'o.example' },
    ],
  });
  const bl = recs.find((r) => r.area === 'blacklist');
  assert.ok(bl);
  assert.equal(bl.severity, 'critical');
  assert.equal(bl.action.url, 'https://check.spamhaus.org/');
});

test('flags missing SPF / DKIM / DMARC', () => {
  const recs = recommend({
    auth: { spf: { present: false }, dkim: { present: false }, dmarc: { present: false } },
    table: [],
  });
  const areas = recs.map((r) => r.area).sort();
  assert.deepEqual(areas, ['dkim', 'dmarc', 'spf']);
});

test('flags DMARC p=none as improvable, not missing', () => {
  const recs = recommend({ auth: { dmarc: { present: true, policy: 'none' } }, table: [] });
  const d = recs.find((r) => r.area === 'dmarc');
  assert.match(d.title, /p=none/);
});

test('recommendations are sorted by severity', () => {
  const recs = recommend({
    auth: { dmarc: { present: true, policy: 'quarantine' }, spf: { present: false } },
    table: [{ state: 'listed', name: 'X', zone: 'z', subject: 'd', severity: 'critical', delist: 'u' }],
  });
  const ranks = { critical: 0, high: 1, medium: 2, low: 3 };
  for (let i = 1; i < recs.length; i++) {
    assert.ok(ranks[recs[i - 1].severity] <= ranks[recs[i].severity]);
  }
});

test('riskScore blends blacklist and auth, sets standing', () => {
  const good = riskScore({ bl: { score: 100 }, auth: { score: 100 } });
  assert.equal(good.score, 100);
  assert.equal(good.standing, 'good standing');
  const poor = riskScore({ bl: { score: 30 }, auth: { score: 20 } });
  assert.equal(poor.standing, 'poor');
});

test('analyzeDomain returns error for invalid input', async () => {
  const r = await analyzeDomain('not_a_domain_zz');
  assert.equal(r.ok, false);
});
