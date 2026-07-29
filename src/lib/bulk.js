import { checkDomain } from './check.js';
import { analyzeDomain } from './analyze.js';
import { buildResolver } from './resolve.js';

/**
 * Check many domains with a bounded concurrency pool.
 *
 * Each single domain check already fans out to ~20 DNS queries, so we do NOT
 * run all domains at once. That would swamp the resolver and trip DNSBL rate
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
  // withAuth also pulls SPF, DKIM, DMARC, MX and PTR for every domain, which is
  // what you want when auditing a client list rather than just hunting listings.
  const checkFn = opts.checkFn || (opts.withAuth ? auditDomain : checkDomain);

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

/**
 * A full audit of one domain: blocklists plus authentication. Returned in the
 * same shape as checkDomain() so everything downstream keeps working, with an
 * extra `auth` block.
 */
async function auditDomain(input, opts = {}) {
  const r = await analyzeDomain(input, opts);
  if (!r.ok) return r;
  const bl = r.blacklist;
  return {
    ok: true,
    input: r.input,
    domain: r.domain,
    verdict: bl.verdict,
    score: bl.score,
    riskScore: r.riskScore,
    standing: r.standing,
    counts: { listed: bl.listedCount, clean: bl.okCount, unknown: bl.timeoutCount, skipped: bl.skippedCount },
    dns: r.dns,
    listings: bl.listings,
    auth: r.auth && {
      score: r.auth.score,
      spf: r.auth.spf.present ? (r.auth.spf.status === 'pass' ? 'pass' : 'weak') : 'missing',
      spfPolicy: r.auth.spf.policy || '',
      dkim: r.auth.dkim.present ? 'pass' : 'none',
      dkimSelectors: (r.auth.dkim.selectors || []).map((x) => x.selector).join(' '),
      dmarc: r.auth.dmarc.present ? (r.auth.dmarc.policy === 'reject' ? 'pass' : 'weak') : 'missing',
      dmarcPolicy: r.auth.dmarc.policy || '',
      mx: (r.auth.mx && r.auth.mx.records.length) || 0,
      ptr: r.auth.ptr ? r.auth.ptr.status : 'n/a',
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
  const withAuth = results.some((r) => r && r.auth);
  const head = ['input', 'domain', 'verdict', 'score', 'listed', 'clean', 'unknown', 'a_records', 'listings', 'error'];
  if (withAuth) {
    head.splice(2, 0, 'risk_score', 'auth_score', 'spf', 'spf_policy', 'dkim', 'dkim_selectors', 'dmarc', 'dmarc_policy', 'mx', 'ptr');
  }
  const rows = [head.join(',')];
  for (const r of results) {
    const a = r.auth || {};
    const authCells = withAuth
      ? [r.riskScore ?? '', a.score ?? '', a.spf ?? '', a.spfPolicy ?? '', a.dkim ?? '', a.dkimSelectors ?? '',
         a.dmarc ?? '', a.dmarcPolicy ?? '', a.mx ?? '', a.ptr ?? '']
      : [];
    const cells = r.ok
      ? [
          r.input,
          r.domain,
          ...authCells,
          r.verdict,
          r.score,
          r.counts.listed,
          r.counts.clean,
          r.counts.unknown,
          r.dns.a.join(' '),
          r.listings.map((l) => `${l.subject}@${l.zone}`).join(' '),
          '',
        ]
      : [r.input, '', ...(withAuth ? authCells.map(() => '') : []), 'invalid', '', '', '', '', '', '', r.error];
    rows.push(cells.map(csvCell).join(','));
  }
  return rows.join('\n');
}

function csvCell(v) {
  let s = String(v ?? '');
  // Neutralize spreadsheet formula injection: a cell beginning with = + - @
  // (or tab/CR) is executed as a formula by Excel/Sheets. Prefix with a quote.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
