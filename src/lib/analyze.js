import { checkDomain } from './check.js';
import { checkAuth } from './auth.js';
import { recommend } from './recommend.js';
import { buildResolver } from './resolve.js';
import { deliverabilityScore, reputationReport } from './deliverability.js';

/**
 * Unified deliverability report. The data behind the Overview dashboard.
 * Combines the blacklist check and authentication health into one risk score,
 * plus recommendations and a placeholder for ESP-sourced signals.
 *
 * @param {string} input  domain or IP
 * @param {object} [opts] { resolver, signals }  (signals = ESP metrics, if any)
 */
export async function analyzeDomain(input, opts = {}) {
  const resolver = opts.resolver || buildResolver();

  const bl = await checkDomain(input, {
    resolver,
    calibration: opts.calibration,
    overallTimeoutMs: opts.overallTimeoutMs,
  });
  if (!bl.ok) return { ok: false, input, error: bl.error };

  // Auth only makes sense for a domain (not a bare IP literal).
  const auth = bl.isIp
    ? null
    : await checkAuth(bl.domain, { resolver, ips: bl.resolvesTo });

  const risk = riskScore({ bl, auth });
  const recommendations = recommend({ auth, table: bl.table });

  // The complete DNS record set for the Email auth page: NS and the full TXT
  // list on top of what the check already resolved. Failures read as empty,
  // never as errors; a record page must not die because one lookup was slow.
  let dnsRecords = null;
  if (!bl.isIp) {
    // Guarded call: a resolver may not implement every method (test stubs,
    // minimal custom resolvers), and a missing method throws synchronously,
    // which is not the same failure as a lookup that errored. A failure comes
    // back as null, never as [] - "could not look up" and "none published" are
    // different answers and the page must not show a timeout as "no records".
    const safe = (fn) => {
      try { return Promise.resolve(fn()).catch(() => null); } catch { return Promise.resolve(null); }
    };
    const [ns, txt] = await Promise.all([
      safe(() => resolver.resolveNs(bl.domain)),
      safe(() => resolver.resolveTxt(bl.domain)).then((r) => (r ? r.map((x) => (Array.isArray(x) ? x.join('') : String(x))) : null)),
    ]);
    dnsRecords = { ns, txt };
  }

  return {
    ok: true,
    input,
    domain: bl.domain,
    isIp: bl.isIp,
    resolvesTo: bl.resolvesTo,
    provider: bl.provider,
    dnsError: bl.dnsError,
    checkedAt: bl.checkedAt,
    tookMs: bl.tookMs,

    riskScore: risk.score,
    standing: risk.standing,
    // Each component's own 0-100 score and whether it could be measured. The
    // weights that blend them stay server-side on purpose.
    components: risk.components,

    // Receiver-side reputation systems (Postmaster, SNDS, Talos, PDR). No DNS
    // query can read these, so until an account is connected they are manual
    // lookups, listed with a prefilled URL and excluded from the score.
    reputation: reputationReport({ ip: bl.resolvesTo?.[0] || null, domain: bl.isIp ? null : bl.domain }),

    auth: auth
      ? {
          score: auth.score,
          complete: auth.complete,
          spf: auth.spf,
          dkim: auth.dkim,
          dmarc: auth.dmarc,
          mx: auth.mx,
          ptr: auth.ptr,
        }
      : null,

    blacklist: {
      score: bl.score,
      verdict: bl.verdict,
      // How much the score is actually built on. Alerting should hold off on a
      // low-confidence result rather than message a client about a number that
      // moved because the network was slow.
      confidence: bl.confidence,
      answeredZones: bl.answeredZones,
      coverage: bl.coverage,
      zonesChecked: bl.zonesChecked,
      trustedZones: bl.trustedZones,
      listedCount: bl.listedCount,
      timeoutCount: bl.timeoutCount,
      okCount: bl.okCount,
      skippedCount: bl.skippedCount,
      listings: bl.table.filter((r) => r.state === 'listed'),
      table: bl.table,
    },

    dns: bl.dns,
    dnsRecords,

    // ESP-sourced engagement/reputation metrics. These are NOT derivable from
    // DNS. They come from the sender's ESP/MTA. We surface whatever is provided
    // via opts.signals and mark the rest "not connected" rather than fabricate.
    signals: buildSignals(opts.signals),

    recommendations,
  };
}

/**
 * Blend the measurable components into a single 0-100 deliverability score.
 * Kept under its old name so existing callers and tests keep working.
 */
export function riskScore({ bl, auth, reputation }) {
  // The blend lives in deliverability.js: blocklists carry most of it, the
  // receiver-side reputation systems the next share, and DNS authentication the
  // smallest. A component that could not be measured (no blocklist answered, a
  // bare IP with no domain to authenticate, no reputation feed connected) drops
  // out of the denominator instead of being scored as perfect or as zero.
  return deliverabilityScore({
    blocklist: typeof bl?.score === 'number' ? bl.score : null,
    auth: typeof auth?.score === 'number' ? auth.score : null,
    reputation: typeof reputation === 'number' ? reputation : null,
  });
}

// The signal catalog mirrors the reference tool's "Signal Database Sources".
// `connected` is true only when a value was actually supplied.
const SIGNAL_DEFS = [
  { key: 'senderScore', label: 'Sender Score', unit: '/100', source: 'Validity', cadence: 'daily' },
  { key: 'bounceRate', label: 'Bounce Rate', unit: '%', source: 'ESP / MTA logs', cadence: 'per-send' },
  { key: 'complaintRate', label: 'Spam Complaint Rate', unit: '%', source: 'FBL', cadence: 'per-campaign' },
  { key: 'openRate', label: 'Open Rate', unit: '%', source: 'ESP', cadence: 'per-campaign' },
  { key: 'replyRate', label: 'Reply Rate', unit: '%', source: 'ESP', cadence: 'per-campaign' },
  { key: 'spamTraps', label: 'Spam Traps', unit: '', source: 'Trap monitoring', cadence: 'real-time' },
  { key: 'dailyVolume', label: 'Daily Volume', unit: '', source: 'MTA', cadence: 'daily' },
];

function buildSignals(provided = {}) {
  return SIGNAL_DEFS.map((d) => {
    const value = provided[d.key];
    return {
      ...d,
      value: value ?? null,
      connected: value !== undefined && value !== null,
    };
  });
}
