import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { buildResolver, reverseIp } from './resolve.js';
import { ALL_ZONES, isListedAnswer, isBlockedAnswer, queryHostOf } from './zones.js';

/**
 * DNSBL trust calibration.
 *
 * A blocklist answer is only meaningful if the list actually answers *us*
 * honestly. Three failure modes silently corrupt results:
 *
 *   1. ALWAYS-POSITIVE. Subscription-only lists (e.g. invaluement) answer
 *      "listed" to every query from a non-subscriber. Trusting them produces
 *      FALSE LISTINGS.
 *   2. SILENT. A list we're not authorized for (e.g. Spamhaus via a public
 *      resolver) answers NXDOMAIN to everything, including its own published
 *      test entry. Trusting it produces FALSE "CLEAN" results.
 *   3. BLOCKED. The list answers with a refusal sentinel (127.255.255.x, or
 *      URIBL's 127.0.0.1).
 *
 * We detect all three by probing each zone with a pair the DNSBL contract
 * defines: a test point that MUST be listed and a control that MUST be clean.
 * Only zones that demonstrably discriminate are trusted for scoring.
 *
 * Verdicts:
 *   'verified'      test point listed + control clean  -> fully trustworthy
 *   'answering'     no published test point, but alive and control clean
 *                   -> a positive is meaningful; treated as usable
 *   'always-positive' control came back listed          -> never trust
 *   'silent'        published test point NOT listed     -> "clean" is meaningless
 *   'blocked'       refusal sentinel returned
 *   'dead'          zone does not resolve at all
 */

const TRUSTED = new Set(['verified', 'answering']);
export const isTrusted = (v) => TRUSTED.has(v);

const CACHE_FILE = process.env.DBC_CALIBRATION_FILE || '.calibration.json';
const CACHE_TTL_MS = Number(process.env.DBC_CALIBRATION_TTL_MS ?? 12 * 60 * 60 * 1000);

let cache = null; // { at, resolvers, zones: { [zone]: {verdict, reason} } }

/** Does this DNS zone still exist? A shut down blocklist has no SOA and no NS. */
async function zoneExists(host, resolver) {
  try {
    await resolver.resolveSoa(host);
    return true;
  } catch { /* fall through to NS */ }
  try {
    await resolver.resolveNs(host);
    return true;
  } catch {
    return false;
  }
}

/** Probe one zone: returns { verdict, reason, detail }. */
export async function calibrateZone(z, resolver) {
  const host = queryHostOf(z);
  const ask = async (subject) => {
    const name = z.type === 'ip' ? `${reverseIp(subject)}.${host}` : `${subject}.${host}`;
    try {
      return { codes: await resolver.resolve4(name) };
    } catch (e) {
      return { error: e.code || 'ERROR' };
    }
  };

  const control = await ask(z.control);

  // Refusal sentinel on the control -> we are not authorized.
  if (control.codes && isBlockedAnswer(z, control.codes)) {
    return { verdict: 'blocked', reason: `query refused (${control.codes.join(',')})` };
  }
  // Control came back as a real listing -> the zone answers positive to
  // everything. Its listings would be false positives.
  if (control.codes && isListedAnswer(z, control.codes)) {
    return {
      verdict: 'always-positive',
      reason: 'answers "listed" for a control that can never be listed. Needs a subscription',
      detail: control.codes.join(','),
    };
  }

  const alive = control.error === 'ENOTFOUND' || control.error === 'ENODATA' || Boolean(control.codes);
  if (!alive) {
    // Distinguish a dead zone from a transient resolver problem.
    try {
      await resolver.resolveSoa(host);
    } catch {
      // A DQS zone that won't resolve almost always means a bad/expired key.
      if (z.queryHost) {
        return { verdict: 'blocked', reason: `DQS key rejected or invalid (${control.error}). Check DBC_DQS_KEY` };
      }
      return { verdict: 'dead', reason: `zone does not resolve (${control.error})` };
    }
    return { verdict: 'blocked', reason: `no usable answer (${control.error})` };
  }

  // No published test point. We cannot prove discrimination, so the zone has to
  // at least exist: a shut down list also answers NXDOMAIN to everything, and
  // counting it as clean would be a false all-clear.
  if (!z.testPoint) {
    if (!(await zoneExists(host, resolver))) {
      return { verdict: 'dead', reason: 'this blocklist no longer exists (its DNS zone is gone)' };
    }
    return { verdict: 'answering', reason: 'live and answering, no published test entry to verify against' };
  }

  const tp = await ask(z.testPoint);
  if (tp.codes && isBlockedAnswer(z, tp.codes)) {
    return { verdict: 'blocked', reason: `query refused (${tp.codes.join(',')})` };
  }
  if (tp.codes && isListedAnswer(z, tp.codes)) {
    return { verdict: 'verified', reason: 'test entry listed, control clean', detail: tp.codes.join(',') };
  }
  // The test entry is not listed for us. Two very different causes, so check
  // whether the zone exists at all before blaming it for ignoring us: a shut
  // down blocklist (MSRBL, DRMX, SORBS) answers NXDOMAIN because it is gone,
  // while a live one (Spamhaus via a public resolver) answers NXDOMAIN because
  // it is deliberately ignoring unauthorized queries.
  if (!(await zoneExists(host, resolver))) {
    return { verdict: 'dead', reason: 'this blocklist no longer exists (its DNS zone is gone)' };
  }
  return {
    verdict: 'silent',
    reason: 'the list is up but ignores our queries (its own test entry comes back "not listed")',
  };
}

/** Calibrate every zone. Returns { at, resolvers, zones }. */
export async function calibrateAll({ resolver, log } = {}) {
  const r = resolver || buildResolver(null, { timeout: 6000, tries: 2 });
  const zones = {};
  const list = [...ALL_ZONES];
  let i = 0;
  const concurrency = Number(process.env.DBC_CALIBRATION_CONCURRENCY ?? 8);

  async function worker() {
    while (i < list.length) {
      const z = list[i++];
      const res = await calibrateZone(z, r);
      zones[z.zone] = res;
      if (log) log(`${res.verdict.padEnd(16)} ${z.name}`);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));

  let servers = [];
  try { servers = r.getServers(); } catch { /* ignore */ }
  return { at: Date.now(), resolvers: servers, zones };
}

/** Load calibration from disk if present and fresh. */
export function loadCalibration() {
  if (cache && Date.now() - cache.at < CACHE_TTL_MS) return cache;
  try {
    if (existsSync(CACHE_FILE)) {
      const parsed = JSON.parse(readFileSync(CACHE_FILE, 'utf8'));
      if (parsed && parsed.zones && Date.now() - parsed.at < CACHE_TTL_MS) {
        cache = parsed;
        return cache;
      }
    }
  } catch { /* ignore unreadable cache */ }
  return null;
}

export function saveCalibration(data) {
  cache = data;
  // A run where nothing is trustworthy means the network or resolver was broken
  // at that moment, not that every blocklist died. Persisting it would disable
  // the whole app until the TTL expired, so keep it in memory only.
  const anyTrusted = Object.values(data.zones).some((v) => isTrusted(v.verdict));
  if (!anyTrusted) return data;
  try { writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2)); } catch { /* read-only fs is fine */ }
  return data;
}

/**
 * Get calibration, running it if there is no fresh result. Safe to call
 * concurrently. The in-flight run is shared.
 */
let inFlight = null;
export async function getCalibration({ resolver, force = false } = {}) {
  if (!force) {
    const hit = loadCalibration();
    if (hit) return hit;
  }
  if (inFlight) return inFlight;
  inFlight = calibrateAll({ resolver })
    .then((data) => saveCalibration(data))
    .finally(() => { inFlight = null; });
  return inFlight;
}

/** Summarize verdict counts. */
export function summarize(cal) {
  const t = {};
  for (const v of Object.values(cal.zones)) t[v.verdict] = (t[v.verdict] || 0) + 1;
  return t;
}
