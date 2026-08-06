import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreResults } from '../src/lib/score.js';

test('all clean -> score 100, verdict clean', () => {
  const s = scoreResults([
    { zone: 'a', weight: 40, listed: false },
    { zone: 'b', weight: 20, listed: false },
  ]);
  assert.equal(s.score, 100);
  assert.equal(s.verdict, 'clean');
  assert.equal(s.counts.listed, 0);
});

test('critical listing -> verdict blacklisted', () => {
  const s = scoreResults([
    { zone: 'zen.spamhaus.org', weight: 40, severity: 'critical', listed: true, codes: ['127.0.0.2'], delist: 'x' },
    { zone: 'b', weight: 10, severity: 'low', listed: false },
  ]);
  assert.equal(s.verdict, 'blacklisted');
  assert.ok(s.score < 100);
  assert.equal(s.listings.length, 1);
});

test('weighting: heavy zone drops score more than light zone', () => {
  const heavy = scoreResults([
    { zone: 'h', weight: 40, severity: 'critical', listed: true },
    { zone: 'l', weight: 5, severity: 'low', listed: false },
  ]);
  const light = scoreResults([
    { zone: 'h', weight: 40, severity: 'critical', listed: false },
    { zone: 'l', weight: 5, severity: 'low', listed: true },
  ]);
  assert.ok(heavy.score < light.score);
});

test('timeouts are unknown, excluded from denominator (not treated as clean)', () => {
  const s = scoreResults([
    { zone: 'a', weight: 40, severity: 'critical', listed: true },
    { zone: 'b', weight: 40, listed: null, error: 'ETIMEOUT' },
  ]);
  // Only the answered weight (40 listed / 40 total) counts -> score 0.
  assert.equal(s.score, 0);
  assert.equal(s.counts.unknown, 1);
  assert.equal(s.unknowns.length, 1);
});

test('all unknown -> verdict unknown', () => {
  const s = scoreResults([
    { zone: 'a', weight: 40, listed: null },
    { zone: 'b', weight: 20, listed: null },
  ]);
  assert.equal(s.verdict, 'unknown');
});

test('decorates listing with return-code meaning', () => {
  const s = scoreResults([
    { zone: 'dbl.spamhaus.org', weight: 40, severity: 'critical', listed: true, codes: ['127.0.1.4'], delist: 'x' },
  ]);
  assert.deepEqual(s.listings[0].meanings, ['phishing domain']);
});

// --- An unmeasurable check has no score ------------------------------------
//
// The denominator is the weight that actually answered. That is right, because
// treating a silent list as clean would be a lie. But it has two consequences
// that used to be invisible.

test('nothing answered -> score is null, not 100', () => {
  const s = scoreResults([
    { zone: 'a', weight: 40, listed: null },
    { zone: 'b', weight: 20, listed: null },
  ]);
  assert.equal(s.score, null, 'a domain nobody could check is not a perfect 100');
  assert.equal(s.verdict, 'unknown');
  assert.equal(s.confidence, 'none');
  assert.equal(s.answeredZones, 0);
});

test('an empty result set is unknown, not a clean 100', () => {
  const s = scoreResults([]);
  assert.equal(s.score, null);
  assert.equal(s.verdict, 'unknown');
});

test('a score built on very few answers is marked low confidence', () => {
  // One list answered "listed", everything else timed out. The arithmetic says
  // 0, which is technically true of the sample and useless as a verdict on the
  // domain. It has to be flagged so alerting can hold off.
  const rows = [{ zone: 'zen.spamhaus.org', weight: 40, severity: 'critical', listed: true }];
  for (let i = 0; i < 35; i++) rows.push({ zone: 'z' + i, weight: 5, listed: null });
  const s = scoreResults(rows);
  assert.equal(s.score, 0);
  assert.equal(s.confidence, 'low');
  assert.equal(s.answeredZones, 1);
  assert.ok(s.coverage < 0.1, `coverage should be tiny, got ${s.coverage}`);
});

test('a full set of answers is high confidence', () => {
  const rows = [{ zone: 'zen.spamhaus.org', weight: 40, severity: 'critical', listed: true }];
  for (let i = 0; i < 35; i++) rows.push({ zone: 'z' + i, weight: 5, listed: false });
  const s = scoreResults(rows);
  assert.equal(s.confidence, 'high');
  assert.equal(s.answeredZones, 36);
  assert.equal(s.coverage, 1);
  // Same real-world situation as the previous test, wildly different score.
  assert.ok(s.score > 80, `got ${s.score}, expected the listing to cost only its own weight`);
});
