import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkMany, resultsToCsv } from '../src/lib/bulk.js';

// A fake check function so these tests never touch the network.
function fakeCheck(input) {
  if (input === 'bad..domain') return Promise.resolve({ ok: false, input, error: 'invalid' });
  return Promise.resolve({
    ok: true,
    input,
    domain: input,
    verdict: input === 'listed.com' ? 'listed' : 'clean',
    score: input === 'listed.com' ? 60 : 100,
    counts: { listed: input === 'listed.com' ? 1 : 0, clean: 5, unknown: 0, total: 6 },
    dns: { a: ['1.2.3.4'], aaaa: [], mx: [] },
    listings: input === 'listed.com' ? [{ subject: input, zone: 'dbl.spamhaus.org' }] : [],
  });
}

test('de-dupes inputs and preserves order', async () => {
  const { results } = await checkMany(['a.com', 'a.com', 'b.com'], { checkFn: fakeCheck });
  assert.equal(results.length, 2);
  assert.equal(results[0].input, 'a.com');
  assert.equal(results[1].input, 'b.com');
});

test('skips blanks and reports counts in summary', async () => {
  const { summary, skipped } = await checkMany(
    ['clean.com', '', '  ', 'listed.com', 'bad..domain'],
    { checkFn: fakeCheck },
  );
  assert.equal(summary.total, 3);
  assert.equal(summary.clean, 1);
  assert.equal(summary.listed, 1);
  assert.equal(summary.invalid, 1);
  assert.equal(skipped.blank, 2);
});

test('respects the max cap and reports truncation', async () => {
  const inputs = Array.from({ length: 10 }, (_, i) => `d${i}.com`);
  const { results, skipped } = await checkMany(inputs, { checkFn: fakeCheck, max: 4 });
  assert.equal(results.length, 4);
  assert.equal(skipped.truncated, 6);
  assert.equal(skipped.max, 4);
});

test('honors concurrency without dropping work', async () => {
  let active = 0, peak = 0;
  const slow = async (input) => {
    active += 1; peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 5));
    active -= 1;
    return { ok: true, input, domain: input, verdict: 'clean', score: 100,
      counts: { listed: 0, clean: 1, unknown: 0, total: 1 }, dns: { a: [], aaaa: [], mx: [] }, listings: [] };
  };
  const inputs = Array.from({ length: 12 }, (_, i) => `x${i}.com`);
  const { results } = await checkMany(inputs, { checkFn: slow, concurrency: 3 });
  assert.equal(results.length, 12);
  assert.ok(peak <= 3, `peak concurrency ${peak} should not exceed 3`);
});

test('resultsToCsv produces a header and one row per result, escaping commas', async () => {
  const { results } = await checkMany(['listed.com', 'bad..domain'], { checkFn: fakeCheck });
  const csv = resultsToCsv(results);
  const lines = csv.split('\n');
  assert.match(lines[0], /^input,domain,verdict,score/);
  assert.equal(lines.length, 3); // header + 2 rows
  assert.ok(csv.includes('listed.com'));
  assert.ok(csv.includes('invalid'));
});
