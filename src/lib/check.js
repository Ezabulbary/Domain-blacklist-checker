import { normalizeDomain } from './normalize.js';
import { buildResolver, resolveDomain, reverseIp, queryZone } from './resolve.js';
import { IP_ZONES, DOMAIN_ZONES } from './zones.js';
import { scoreResults } from './score.js';

/**
 * End-to-end check for one domain (plan §3):
 *
 *   normalize -> resolve (A/AAAA/MX) -> parallel fan-out of
 *   (each IPv4 × IP zones) and (domain × domain zones) -> weighted score.
 *
 * Every zone query is bounded by its own 3s timeout; the whole fan-out is
 * additionally capped at `overallTimeoutMs` (default 8s) so one dead zone can't
 * hang the request — anything unfinished is reported as `unknown`, not clean.
 *
 * @param {string} input  raw user input
 * @param {object} [opts] { resolver, overallTimeoutMs }
 */
export async function checkDomain(input, opts = {}) {
  const started = Date.now();
  const norm = normalizeDomain(input);

  if (!norm.isValid) {
    return {
      ok: false,
      input,
      error: norm.error || 'invalid domain',
    };
  }

  const resolver = opts.resolver || buildResolver();
  const overallTimeoutMs = opts.overallTimeoutMs ?? 8000;

  // For a bare IP literal there is no domain-level lookup — only IP zones.
  const dns = norm.isIp
    ? { a: [norm.host], aaaa: [], mx: [], errors: {} }
    : await resolveDomain(norm.domain, resolver);

  // Build the full job list: (ipv4 × ip zone) + (domain × domain zone).
  const jobs = [];
  for (const ip of dns.a) {
    const rev = reverseIp(ip);
    for (const z of IP_ZONES) {
      jobs.push(queryZone(rev, z, resolver).then((r) => ({ ...r, subject: ip })));
    }
  }
  if (!norm.isIp) {
    for (const z of DOMAIN_ZONES) {
      jobs.push(queryZone(norm.domain, z, resolver).then((r) => ({ ...r, subject: norm.domain })));
    }
  }

  const results = await withOverallCap(jobs, overallTimeoutMs);
  const summary = scoreResults(results);

  return {
    ok: true,
    input,
    domain: norm.domain,
    host: norm.host,
    isIp: norm.isIp,
    dns: { a: dns.a, aaaa: dns.aaaa, mx: dns.mx, errors: dns.errors },
    ...summary,
    tookMs: Date.now() - started,
    checkedAt: new Date().toISOString(),
  };
}

/**
 * Await all jobs but never longer than `cap` ms. Jobs that don't finish in time
 * are folded in as `unknown` results so the score math still balances. Each job
 * already resolves (never rejects) thanks to queryZone's try/catch.
 */
async function withOverallCap(jobs, cap) {
  let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => resolve('__TIMEOUT__'), cap);
  });

  const settled = jobs.map((p) =>
    p.then((v) => ({ done: true, v })).catch((e) => ({ done: true, v: { listed: null, error: String(e) } })),
  );

  const race = await Promise.race([Promise.all(settled), deadline]);
  clearTimeout(timer);

  if (race !== '__TIMEOUT__') return race.map((r) => r.v);

  // Timed out: collect whatever finished, mark the rest unknown.
  const snapshot = await Promise.all(
    settled.map((s) =>
      Promise.race([s, Promise.resolve({ done: false })]).catch(() => ({ done: false })),
    ),
  );
  return snapshot.map((r, i) =>
    r.done ? r.v : { listed: null, error: 'OVERALL_TIMEOUT', zone: `job:${i}`, weight: 0 },
  );
}
