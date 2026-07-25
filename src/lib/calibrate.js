import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { buildResolver, reverseIp } from './resolve.js';
import { ALL_ZONES, isListedAnswer, isBlockedAnswer } from './zones.js';

/**
 * DNSBL trust calibration.
 *
 * A blocklist answer is only meaningful if the list actually answers *us*
 * honestly. Three failure modes silently corrupt results:
 *
 *   1. ALWAYS-POSITIVE — subscription-only lists (e.g. invaluement) answer
 *      "listed" to every query from a non-subscriber. Trusting them produces
 *      FALSE LISTINGS.
 *   2. SILENT — a list we're not authorized for (e.g. Spamhaus via a public
 *      resolver) answers NXDOMAIN to everything, including its own published
 *      test entry. Trusting it produces FALSE "CLEAN" results.
 *   3. BLOCKED — the list answers with a refusal sentinel (127.255.255.x, or
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

/** Probe one zone: returns { verdict, reason, detail }. */
export async function calibrateZone(z, resolver) {
  const ask = async (subject) => {
    const name = z.type === 'ip' ? `${reverseIp(subject)}.${z.zone}` : `${subject}.${z.zone}`;
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
      reason: 'answers "listed" for a control that can never be listed — needs a subscription',
      detail: control.codes.join(','),
    };
  }

  const alive = control.error === 'ENOTFOUND' || control.error === 'ENODATA' || Boolean(control.codes);
  if (!alive) {
    // Distinguish a dead zone from a transient resolver problem.
    try {
      await resolver.resolveSoa(z.zone);
    } catch {
      return { verdict: 'dead', reason: `zone does not resolve (${control.error})` };
    }
    return { verdict: 'blocked', reason: `no usable answer (${control.error})` };
  }

  // No published test point -> we cannot prove discrimination, but the zone is
  // answering and is not always-positive, so a positive from it is meaningful.
  if (!z.testPoint) {
    return { verdict: 'answering', reason: 'alive, no published test entry to verify against' };
  }

  const tp = await ask(z.testPoint);
  if (tp.codes && isBlockedAnswer(z, tp.codes)) {
    return { verdict: 'blocked', reason: `query refused (${tp.codes.join(',')})` };
  }
  if (tp.codes && isListedAnswer(z, tp.codes)) {
    return { verdict: 'verified', reason: 'test entry listed, control clean', detail: tp.codes.join(',') };
  }
  // The zone answers, but its own test entry is not listed for us: it is
  // ignoring our queries and would report everything as clean.
  return {
    verdict: 'silent',
    reason: 'ignores our queries (its own test entry returns "not listed") — would report everything as clean',
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
  try { writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2)); } catch { /* read-only fs is fine */ }
  return data;
}

/**
 * Get calibration, running it if there is no fresh result. Safe to call
 * concurrently — the in-flight run is shared.
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
