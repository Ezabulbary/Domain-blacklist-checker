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

test('resultsToCsv neutralizes spreadsheet formula injection', async () => {
  // A malicious "domain" that fails normalization is echoed back in the CSV.
  const evilCheck = (input) => Promise.resolve({ ok: false, input, error: 'invalid' });
  const { results } = await checkMany(['=HYPERLINK("http://evil","x")'], { checkFn: evilCheck });
  const csv = resultsToCsv(results);
  // The dangerous cell must be quoted and prefixed with a single quote so it is
  // not executed as a formula.
  assert.ok(csv.includes(`"'=HYPERLINK`), `expected neutralized cell, got: ${csv}`);
  assert.ok(!/^=HYPERLINK/m.test(csv), 'no raw formula at start of a line');
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

// --- Regression: a large batch must survive a single failing domain ---------
//
// A bulk run of a few hundred domains with authentication enabled was returning
// 500 Internal Server Error. The cause was checkMx() omitting `records` on a
// transient DNS failure (ETIMEOUT/ESERVFAIL), which made auditDomain() throw on
// `records.length`. The throw escaped the worker, rejected the Promise.all in
// checkMany, and destroyed a run that had already spent minutes of DNS queries.
// Small batches passed because they rarely hit a transient failure at all.

test('one throwing domain does not fail the whole batch', async () => {
  const boom = (input) => {
    if (input === 'explodes.com') throw new TypeError("Cannot read properties of undefined (reading 'length')");
    return fakeCheck(input);
  };
  const inputs = ['clean.com', 'explodes.com', 'listed.com'];
  const { results, summary } = await checkMany(inputs, { checkFn: boom, concurrency: 3 });

  assert.equal(results.length, 3, 'every input still gets a row');
  assert.ok(results.every(Boolean), 'no holes in the results array');
  const bad = results.find((r) => r.input === 'explodes.com');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /check failed/);
  // The domains that did work are still reported.
  assert.equal(summary.clean, 1);
  assert.equal(summary.listed, 1);
  assert.equal(summary.invalid, 1);
  // And the CSV export still renders.
  assert.equal(resultsToCsv(results).split('\n').length, 4);
});

test('checkMx always returns a records array, even on a transient failure', async () => {
  const { checkMx } = await import('../src/lib/auth.js');
  for (const code of ['ETIMEOUT', 'ESERVFAIL', 'EREFUSED', 'ENOTFOUND', 'ENODATA']) {
    const resolver = { resolveMx: async () => { const e = new Error(code); e.code = code; throw e; } };
    const mx = await checkMx('example.com', resolver);
    assert.ok(Array.isArray(mx.records), `records must be an array for ${code}`);
    // This is the exact expression that used to throw.
    assert.equal(mx.records.length || 0, 0);
  }
});

test('the auth audit path survives a resolver that fails every lookup', async () => {
  const fail = async () => { const e = new Error('x'); e.code = 'ETIMEOUT'; throw e; };
  const hostile = { resolve4: fail, resolve6: fail, resolveTxt: fail, resolveMx: fail, reverse: fail };
  const { results, summary } = await checkMany(['a.com', 'b.com'], {
    resolver: hostile,
    withAuth: true,
    calibration: false,
    concurrency: 2,
  });
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r && typeof r.ok === 'boolean'));
  assert.equal(summary.total, 2);
  assert.doesNotThrow(() => resultsToCsv(results));
});
