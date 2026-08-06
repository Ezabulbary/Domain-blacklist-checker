import { RETURN_CODES } from './zones.js';

/**
 * Turn raw per-zone results into a weighted 0-100 reputation score plus a
 * verdict. 100 = clean, 0 = badly listed. We weight by zone importance so a
 * Spamhaus hit tanks the score while a SORBS hit barely moves it (plan §3/§5.6).
 *
 * `results` is a flat array of queryZone() outputs, each optionally carrying a
 * `subject` (the IP or domain it was about).
 */
// Below this many answering lists the score is arithmetic on a sample too small
// to act on. It is still returned, but marked so alerting can hold off rather
// than wake a client over a number that moved because the network was slow.
const MIN_CONFIDENT_ZONES = 10;

export function scoreResults(results) {
  const listed = results.filter((r) => r.listed === true);
  const unknown = results.filter((r) => r.listed === null);
  const clean = results.filter((r) => r.listed === false);

  // Denominator is the total weight we actually got a definitive answer for,
  // so a pile of timeouts doesn't silently inflate the score. Treating an
  // unanswered list as clean would be the same lie as calling a domain clean
  // because a blocklist never replied.
  const answered = [...listed, ...clean];
  const answeredWeight = answered.reduce((s, r) => s + (r.weight || 0), 0);
  const listedWeight = listed.reduce((s, r) => s + (r.weight || 0), 0);

  // With nothing answered there is no score to give. Returning 100 here would
  // report a domain nobody could check as perfectly clean.
  const score = answeredWeight === 0
    ? null
    : Math.round(100 - (listedWeight / answeredWeight) * 100);

  // That denominator has a consequence worth surfacing: the fewer lists that
  // answer, the more violently the score swings. One list answering "listed"
  // and the rest timing out scores 0, the same domain with a full set of
  // answers scores 85. The number is not wrong, it is just built on very little,
  // so say how much it is built on rather than let a caller trust it blindly.
  const coverage = answered.length + unknown.length === 0
    ? 0
    : answered.length / (answered.length + unknown.length);
  const confidence = answered.length === 0 ? 'none'
    : (answered.length < MIN_CONFIDENT_ZONES || coverage < 0.5) ? 'low'
    : 'high';

  let verdict;
  if (listed.some((r) => r.severity === 'critical')) verdict = 'blacklisted';
  else if (listed.length > 0) verdict = 'listed';
  else if (answered.length === 0) verdict = 'unknown';
  else verdict = 'clean';

  return {
    score,
    verdict,
    confidence,
    answeredZones: answered.length,
    answeredWeight,
    coverage: Math.round(coverage * 100) / 100,
    counts: {
      listed: listed.length,
      clean: clean.length,
      unknown: unknown.length,
      total: results.length,
    },
    listings: listed.map(decorate),
    unknowns: unknown.map((r) => ({
      zone: r.zone,
      subject: r.subject,
      reason: r.error || 'no response',
    })),
  };
}

/** Attach human-readable return-code meaning + delist guidance to a listing. */
function decorate(r) {
  const map = RETURN_CODES[r.zone];
  const meanings = map && r.codes ? r.codes.map((c) => map[c]).filter(Boolean) : [];
  return {
    zone: r.zone,
    subject: r.subject,
    severity: r.severity,
    note: r.note,
    codes: r.codes || [],
    meanings,
    delist: r.delist,
  };
}
