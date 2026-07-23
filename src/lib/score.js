import { RETURN_CODES } from './zones.js';

/**
 * Turn raw per-zone results into a weighted 0-100 reputation score plus a
 * verdict. 100 = clean, 0 = badly listed. We weight by zone importance so a
 * Spamhaus hit tanks the score while a SORBS hit barely moves it (plan §3/§5.6).
 *
 * `results` is a flat array of queryZone() outputs, each optionally carrying a
 * `subject` (the IP or domain it was about).
 */
export function scoreResults(results) {
  const listed = results.filter((r) => r.listed === true);
  const unknown = results.filter((r) => r.listed === null);
  const clean = results.filter((r) => r.listed === false);

  // Denominator is the total weight we actually got a definitive answer for,
  // so a pile of timeouts doesn't silently inflate the score.
  const answered = [...listed, ...clean];
  const totalWeight = answered.reduce((s, r) => s + (r.weight || 0), 0) || 1;
  const listedWeight = listed.reduce((s, r) => s + (r.weight || 0), 0);

  const score = Math.round(100 - (listedWeight / totalWeight) * 100);

  let verdict;
  if (listed.some((r) => r.severity === 'critical')) verdict = 'blacklisted';
  else if (listed.length > 0) verdict = 'listed';
  else if (clean.length === 0 && unknown.length > 0) verdict = 'unknown';
  else verdict = 'clean';

  return {
    score,
    verdict,
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
