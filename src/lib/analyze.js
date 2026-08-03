import { checkDomain } from './check.js';
import { checkAuth } from './auth.js';
import { recommend } from './recommend.js';
import { buildResolver } from './resolve.js';

/**
 * Unified deliverability report. The data behind the Overview dashboard.
 * Combines the blacklist check and authentication health into one risk score,
 * plus recommendations and a placeholder for ESP-sourced signals.
 *
 * @param {string} input  domain or IP
 * @param {object} [opts] { resolver, signals, withRecords }
 *                        (signals = ESP metrics; withRecords includes the full
 *                        DNS record set under auth.records; see checkAuth)
 */
export async function analyzeDomain(input, opts = {}) {
  const resolver = opts.resolver || buildResolver();

  const bl = await checkDomain(input, {
    resolver,
    calibration: opts.calibration,
    overallTimeoutMs: opts.overallTimeoutMs,
  });
  if (!bl.ok) return { ok: false, input, error: bl.error };

  // Auth only makes sense for a domain (not a bare IP literal). Auth TXT
  // lookups want a patient resolver (5s, 2 tries), not the DNSBL-tuned one, so
  // a caller can pass a dedicated `authResolver`; otherwise the shared one is
  // reused (checkAuth builds its own patient resolver only when none is given).
  const auth = bl.isIp
    ? null
    : await checkAuth(bl.domain, {
        resolver: opts.authResolver || resolver,
        ips: bl.resolvesTo,
        withRecords: opts.withRecords,
      });

  const risk = riskScore({ bl, auth });
  const recommendations = recommend({ auth, table: bl.table });

  return {
    ok: true,
    input,
    domain: bl.domain,
    isIp: bl.isIp,
    resolvesTo: bl.resolvesTo,
    dnsError: bl.dnsError,
    checkedAt: bl.checkedAt,
    tookMs: bl.tookMs,

    riskScore: risk.score,
    standing: risk.standing,

    auth: auth
      ? {
          score: auth.score,
          spf: auth.spf,
          dkim: auth.dkim,
          dmarc: auth.dmarc,
          mx: auth.mx,
          ptr: auth.ptr,
          records: auth.records || null,
        }
      : null,

    blacklist: {
      score: bl.score,
      verdict: bl.verdict,
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

    // ESP-sourced engagement/reputation metrics. These are NOT derivable from
    // DNS. They come from the sender's ESP/MTA. We surface whatever is provided
    // via opts.signals and mark the rest "not connected" rather than fabricate.
    signals: buildSignals(opts.signals),

    recommendations,
  };
}

/**
 * Blend authentication health and blacklist reputation into a single 0-100
 * risk score. Blacklist reputation is weighted a bit heavier than auth.
 */
export function riskScore({ bl, auth }) {
  const blScore = bl.score ?? 100;
  const authS = auth ? auth.score : 100;
  const score = Math.round(blScore * 0.6 + authS * 0.4);
  let standing = 'good standing';
  if (score < 50) standing = 'poor';
  else if (score < 80) standing = 'at risk';
  return { score, standing };
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
