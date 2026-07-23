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
