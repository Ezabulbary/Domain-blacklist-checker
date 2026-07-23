import { checkDomain } from './check.js';
import { buildResolver } from './resolve.js';

/**
 * Check many domains with a bounded concurrency pool.
 *
 * Each single domain check already fans out to ~20 DNS queries, so we do NOT
 * run all domains at once — that would swamp the resolver and trip DNSBL rate
 * limits (plan §5.3/§5.5). We run `concurrency` domains in parallel and stream
 * through the rest as slots free up.
 *
 * Duplicate inputs are de-duped (by normalized lowercase form) so a messy CSV
 * doesn't waste queries. Order of `results` follows the de-duped input order.
 *
 * @param {string[]} inputs   raw domain strings (from textarea, CSV, file…)
 * @param {object}  [opts]    { concurrency=5, resolver, overallTimeoutMs, onProgress, max=500, checkFn }
 *                            checkFn(input, {resolver, overallTimeoutMs}) lets the caller
 *                            wrap the check (e.g. to add a cache); defaults to checkDomain.
 * @returns {{ results: object[], summary: object, skipped: object }}
 */
export async function checkMany(inputs, opts = {}) {
  const started = Date.now();
  const concurrency = Math.max(1, Math.min(opts.concurrency ?? 5, 16));
  const max = opts.max ?? 500;
  const resolver = opts.resolver || buildResolver();
  const checkFn = opts.checkFn || checkDomain;

  // Clean + de-dupe while preserving first-seen order.
  const seen = new Set();
  const queue = [];
  let blank = 0;
  for (const raw of inputs) {
    const s = (raw ?? '').toString().trim();
    if (!s) {
      blank += 1;
      continue;
    }
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    queue.push(s);
  }

  const truncated = queue.length > max;
  const work = truncated ? queue.slice(0, max) : queue;

  const results = new Array(work.length);
  let next = 0;
  let done = 0;

  async function worker() {
    while (true) {
      const i = next++;
      if (i >= work.length) return;
      results[i] = await checkFn(work[i], {
        resolver,
        overallTimeoutMs: opts.overallTimeoutMs,
      });
      done += 1;
      if (opts.onProgress) opts.onProgress(done, work.length);
    }
  }

  const pool = Array.from({ length: Math.min(concurrency, work.length) }, worker);
  await Promise.all(pool);

  return {
    results,
    summary: summarize(results, Date.now() - started),
    skipped: {
      blank,
      duplicates: queue.length - new Set(queue.map((q) => q.toLowerCase())).size,
      truncated: truncated ? queue.length - max : 0,
      max,
    },
  };
}

function summarize(results, tookMs) {
  const s = { total: results.length, clean: 0, listed: 0, blacklisted: 0, unknown: 0, invalid: 0, tookMs };
  for (const r of results) {
    if (!r.ok) s.invalid += 1;
    else s[r.verdict] = (s[r.verdict] ?? 0) + 1;
  }
  return s;
}

/**
 * Flatten bulk results into CSV rows for export/download. One line per domain.
 */
export function resultsToCsv(results) {
  const head = ['input', 'domain', 'verdict', 'score', 'listed', 'clean', 'unknown', 'a_records', 'listings', 'error'];
  const rows = [head.join(',')];
  for (const r of results) {
    const cells = r.ok
      ? [
          r.input,
          r.domain,
          r.verdict,
          r.score,
          r.counts.listed,
          r.counts.clean,
          r.counts.unknown,
          r.dns.a.join(' '),
          r.listings.map((l) => `${l.subject}@${l.zone}`).join(' '),
          '',
        ]
      : [r.input, '', 'invalid', '', '', '', '', '', '', r.error];
    rows.push(cells.map(csvCell).join(','));
  }
  return rows.join('\n');
}

function csvCell(v) {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
