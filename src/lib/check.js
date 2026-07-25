import { normalizeDomain } from './normalize.js';
import { buildResolver, resolveDomain, reverseIp, queryZone } from './resolve.js';
import { IP_ZONES, DOMAIN_ZONES, RETURN_CODES } from './zones.js';
import { scoreResults } from './score.js';
import { getCalibration, isTrusted } from './calibrate.js';

/**
 * End-to-end check for one domain (mxtoolbox-style):
 *
 *   normalize -> resolve (A/AAAA/MX) -> parallel fan-out of
 *   (each IPv4 × IP zones) and (domain × domain zones) -> weighted score
 *   + a full per-zone results table (LISTED / OK / TIMEOUT).
 *
 * Every zone query is bounded by its own 3s timeout; the whole fan-out is
 * additionally capped at `overallTimeoutMs` so one dead zone can't hang the
 * request — anything unfinished is reported as a TIMEOUT (unknown), not clean.
 *
 * @param {string} input  raw user input
 * @param {object} [opts] { resolver, overallTimeoutMs }
 */
export async function checkDomain(input, opts = {}) {
  const started = Date.now();
  const norm = normalizeDomain(input);

  if (!norm.isValid) {
    return { ok: false, input, error: norm.error || 'invalid domain' };
  }

  // A resolver tuned for DNSBL queries: a couple of built-in retries and a
  // slightly longer timeout mean a slow-but-alive list answers instead of
  // being reported as a timeout.
  const resolver = opts.resolver || buildResolver(null, { timeout: 5000, tries: 2 });
  const overallTimeoutMs = opts.overallTimeoutMs ?? 25000;
  // Query a moderate number at a time — firing all ~120 at once overloads the
  // resolver and *causes* timeouts, which is the opposite of what we want.
  const concurrency = opts.concurrency ?? Number(process.env.DBC_QUERY_CONCURRENCY ?? 12);
  const retries = opts.retries ?? Number(process.env.DBC_QUERY_RETRIES ?? 2);
  // Most listings are per-IP; checking every A record of a big CDN domain
  // multiplies the query count for little value. Cap the IPs we test.
  const maxIps = opts.maxIps ?? Number(process.env.DBC_MAX_IPS ?? 2);

  // For a bare IP literal there is no domain-level lookup — only IP zones.
  const dns = norm.isIp
    ? { a: [norm.host], aaaa: [], mx: [], errors: {} }
    : await resolveDomain(norm.domain, resolver);

  // No A record AND the lookups errored (not a clean NXDOMAIN) means the
  // resolver itself couldn't reach a DNS server — every domain then looks empty
  // and "the same". Surface it so the UI can tell the user to set DBC_RESOLVERS.
  const dnsError = !norm.isIp && dns.a.length === 0 && Object.keys(dns.errors).length > 0;

  // Decide which zones to actually query, from live calibration (see
  // calibrate.js). Only lists that provably answer US honestly are queried:
  // a subscription-only list that answers "listed" to everything would create
  // FALSE LISTINGS, and a list that silently ignores us would create FALSE
  // "CLEAN" results. Both are excluded and reported as "skipped" with the
  // reason, so the numbers you see are only from lists that actually work.
  const cal = opts.calibration === false ? null : opts.calibration || (await getCalibration({ resolver }).catch(() => null));

  const trustKeyed = process.env.DBC_TRUST_KEYED === 'true';
  const shouldQuery = (z) => {
    const v = cal && cal.zones && cal.zones[z.zone];
    if (v) return isTrusted(v.verdict);
    // No calibration available — fall back to the static catalog status.
    return z.status !== 'defunct' && !(z.status === 'requiresKey' && !trustKeyed);
  };
  const skipRow = (z, subject) => {
    const v = cal && cal.zones && cal.zones[z.zone];
    return {
      ...z,
      subject,
      skipped: true,
      error: v ? v.verdict.toUpperCase().replace(/-/g, '_') : (z.status === 'defunct' ? 'INACTIVE' : 'NEEDS_KEY'),
      skipReason: v ? v.reason : (z.status === 'defunct' ? 'list inactive' : 'needs key (set DBC_TRUST_KEYED)'),
    };
  };

  // Build the job list, keeping each job's identity (meta + subject) so a job
  // that misses the overall cap can still be reported as its own zone row.
  const ipsToCheck = [...new Set(dns.a)].slice(0, maxIps);
  const jobs = [];
  const skippedRows = [];
  const primaryIp = ipsToCheck[0] || null;
  for (const z of IP_ZONES) {
    if (shouldQuery(z)) {
      for (const ip of ipsToCheck) {
        const rev = reverseIp(ip);
        jobs.push({ meta: z, subject: ip, run: () => queryZone(rev, z, resolver) });
      }
    } else if (primaryIp) {
      skippedRows.push(skipRow(z, primaryIp));
    }
  }
  if (!norm.isIp) {
    for (const z of DOMAIN_ZONES) {
      if (shouldQuery(z)) jobs.push({ meta: z, subject: norm.domain, run: () => queryZone(norm.domain, z, resolver) });
      else skippedRows.push(skipRow(z, norm.domain));
    }
  }

  const raw = await runWithRetry(jobs, concurrency, overallTimeoutMs, retries);
  const results = raw.map((r) => ({ ...r, subject: r.subject ?? r._subject }));

  // Weighted score / verdict / listings / unknowns — only over queried zones.
  const summary = scoreResults(results);

  // Full per-zone table: queried rows + skipped (inactive / needs-key) rows.
  const table = [...results, ...skippedRows].map(toRow);
  const listedCount = table.filter((r) => r.state === 'listed').length;
  const timeoutCount = table.filter((r) => r.state === 'timeout').length;
  const okCount = table.filter((r) => r.state === 'ok').length;
  const skippedCount = table.filter((r) => r.state === 'skipped').length;
  // How many distinct blocklists actually answered us — the meaningful number.
  const trustedZones = new Set(table.filter((r) => r.state !== 'skipped').map((r) => r.zone)).size;

  // Sort: listed → timeout → ok → skipped; alphabetical within each group.
  const order = { listed: 0, timeout: 1, ok: 2, skipped: 3 };
  table.sort((a, b) => order[a.state] - order[b.state] || a.name.localeCompare(b.name));

  const zonesChecked = IP_ZONES.length + (norm.isIp ? 0 : DOMAIN_ZONES.length);

  return {
    ok: true,
    input,
    domain: norm.domain,
    host: norm.host,
    isIp: norm.isIp,
    resolvesTo: dns.a,
    dnsError,
    dns: { a: dns.a, aaaa: dns.aaaa, mx: dns.mx, errors: dns.errors },
    zonesChecked,
    trustedZones,
    listedCount,
    timeoutCount,
    okCount,
    skippedCount,
    table,
    ...summary,
    tookMs: Date.now() - started,
    checkedAt: new Date().toISOString(),
  };
}

/** Normalize a raw zone result into a display row for the results table. */
function toRow(r) {
  const state = r.skipped
    ? 'skipped'
    : r.listed === true ? 'listed' : r.listed === false ? 'ok' : 'timeout';
  const codeMap = RETURN_CODES[r.zone];
  const meanings = codeMap && r.codes ? r.codes.map((c) => codeMap[c]).filter(Boolean) : [];
  let reason = '';
  if (state === 'listed') reason = `${r.subject} was listed`;
  else if (state === 'timeout') reason = timeoutReason(r);
  else if (state === 'skipped') reason = r.skipReason || 'not queried';
  return {
    name: r.name || r.zone,
    zone: r.zone,
    type: r.type || 'ip',
    category: r.category || 'ip',
    severity: r.severity || 'low',
    subject: r.subject,
    state, // 'listed' | 'ok' | 'timeout' | 'skipped'
    codes: r.codes || [],
    meanings,
    ttl: r.ttl ?? null,
    responseMs: r.responseMs ?? null,
    reason,
    note: r.note || '',
    delist: r.delist || null,
    catalogStatus: r.status || 'live', // live | requiresKey | defunct | unverified
    error: r.error || null,
  };
}

function timeoutReason(r) {
  if (r.error === 'PUBLIC_RESOLVER_BLOCKED') return 'blocked (needs private resolver / key)';
  if (r.error === 'REQUIRES_KEY') return 'requires key (unverified via public resolver)';
  if (r.error === 'OVERALL_TIMEOUT') return 'timed out';
  return r.error ? r.error.toLowerCase() : 'no response';
}

// A timeout worth retrying is one where we got no definitive answer for a
// transient/network reason — NOT a "needs a key" / "blocked" result, which a
// retry can't fix.
const PERMANENT = new Set(['REQUIRES_KEY', 'PUBLIC_RESOLVER_BLOCKED']);
const isRetryable = (r) => r && r.listed === null && !PERMANENT.has(r.error);

/**
 * Run the jobs, then retry the ones that timed out for transient reasons a few
 * times (at lower concurrency, so the retries themselves don't re-overload the
 * resolver). This is what turns a wall of TIMEOUTs into real OK/LISTED answers.
 */
async function runWithRetry(jobs, concurrency, cap, retries) {
  let results = await runPool(jobs, concurrency, cap);
  for (let attempt = 0; attempt < retries; attempt++) {
    const idx = results.map((r, i) => (isRetryable(r) ? i : -1)).filter((i) => i >= 0);
    if (idx.length === 0) break;
    const retried = await runPool(idx.map((i) => jobs[i]), Math.max(4, Math.floor(concurrency / 2)), cap);
    idx.forEach((orig, k) => {
      // Keep the retry only if it's an improvement (a definitive answer).
      if (retried[k] && retried[k].listed !== null) results[orig] = retried[k];
    });
  }
  return results;
}

/**
 * Run all jobs through a bounded concurrency pool, never exceeding `cap` ms
 * overall. Running a few dozen at a time (instead of all ~140 at once) avoids
 * swamping the resolver — which itself causes spurious timeouts — and is the
 * polite thing to do to the DNSBLs (plan §5.5). Jobs still unfinished when the
 * cap fires are folded in as their own zone row with a TIMEOUT state, so the
 * table always lists every blacklist. Each job resolves (never rejects).
 */
async function runPool(jobs, concurrency, cap) {
  const results = new Array(jobs.length);
  const done = new Array(jobs.length).fill(false);
  let next = 0;

  async function worker() {
    while (true) {
      const i = next++;
      if (i >= jobs.length) return;
      const j = jobs[i];
      try {
        results[i] = { ...(await j.run()), subject: j.subject };
      } catch (e) {
        results[i] = { ...j.meta, subject: j.subject, listed: null, error: String(e?.code || e) };
      }
      done[i] = true;
    }
  }

  const pool = Promise.all(
    Array.from({ length: Math.min(concurrency, jobs.length) }, worker),
  );
  const deadline = new Promise((resolve) => setTimeout(() => resolve('__TIMEOUT__'), cap));
  const race = await Promise.race([pool, deadline]);

  if (race !== '__TIMEOUT__') return results;

  // Cap fired: keep finished results, mark the rest TIMEOUT with full identity.
  return jobs.map((j, i) =>
    done[i] ? results[i] : { ...j.meta, subject: j.subject, listed: null, error: 'OVERALL_TIMEOUT' },
  );
}
