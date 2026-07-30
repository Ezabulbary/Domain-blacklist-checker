import { buildResolver, reverseIp, queryZone } from './resolve.js';
import { ALL_ZONES, isListedAnswer } from './zones.js';

// Assisted delisting.
//
// Fully automatic removal is not possible and not permitted: the removal forms
// carry CAPTCHAs, several lists confirm by email to postmaster@ or abuse@, some
// need a human to review, and most forbid automated submissions outright. A bot
// hammering them gets this server banned, which is the opposite of helping.
//
// What CAN be automated, and is:
//   1. Readiness. Check, from DNS, whether the sender meets the list's stated
//      requirements, so a request is not rejected on submission.
//   2. Prefill. Open the removal page with the IP or domain already filled in.
//   3. Watch. Re-query the list until the entry actually disappears.
//   4. Skip pointless work. Several lists expire on their own, so the correct
//      action is to fix the cause and wait, not to submit anything.

// Lists that drop the entry by themselves once the cause stops. For these there
// is nothing to submit, so the flow is: fix, then watch.
export const AUTO_CLEARING = {
  'bl.spamcop.net': 'about 24 hours after the last report',
  'dnsbl-1.uceprotect.net': '7 days after the last event',
  'ips.backscatterer.org': 'once the backscatter stops',
  'truncate.gbudb.net': 'as the IP sends normal mail again',
  'bl.blocklist.de': 'about 48 hours without new reports',
  'psbl.surriel.com': 'automatically, or immediately via the form',
};

// Removal or lookup pages that accept the subject in the URL, so the operator
// lands on a page that is already filled in.
const PREFILL = {
  'zen.spamhaus.org': (s) => `https://check.spamhaus.org/listed/?searchterm=${encodeURIComponent(s)}`,
  'dbl.spamhaus.org': (s) => `https://check.spamhaus.org/listed/?searchterm=${encodeURIComponent(s)}`,
  'bl.spamcop.net': (s) => `https://www.spamcop.net/w3m?action=checkblock&ip=${encodeURIComponent(s)}`,
  'dnsbl-1.uceprotect.net': (s) => `https://www.uceprotect.net/en/rblcheck.php?ipr=${encodeURIComponent(s)}`,
  'dnsbl-2.uceprotect.net': (s) => `https://www.uceprotect.net/en/rblcheck.php?ipr=${encodeURIComponent(s)}`,
  'dnsbl-3.uceprotect.net': (s) => `https://www.uceprotect.net/en/rblcheck.php?ipr=${encodeURIComponent(s)}`,
  'psbl.surriel.com': (s) => `https://psbl.org/remove?ip=${encodeURIComponent(s)}`,
  'bl.blocklist.de': (s) => `https://www.blocklist.de/en/search.html?ip=${encodeURIComponent(s)}`,
  'dnsbl.dronebl.org': (s) => `https://dronebl.org/lookup?ip=${encodeURIComponent(s)}`,
  'b.barracudacentral.org': (s) => `https://www.barracudacentral.org/lookups/lookup-reputation?ip=${encodeURIComponent(s)}`,
  'rbl.interserver.net': (s) => `https://rbl.interserver.net/?ip=${encodeURIComponent(s)}`,
  'dnsbl.spfbl.net': (s) => `https://spfbl.net/en/delist/?query=${encodeURIComponent(s)}`,
};

export function prefillUrl(zone, subject) {
  const z = ALL_ZONES.find((x) => x.zone === zone);
  if (!z) return null;
  const f = PREFILL[zone];
  return f && subject ? f(subject) : z.delist || null;
}

const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s || '');

/**
 * Check, from live DNS, whether this sender meets what the list expects before
 * it will accept a removal. Every item is a real lookup, not a reminder.
 *
 * Returns { ready, checks: [{ label, ok, detail, required }] }.
 */
export async function readiness({ zone, subject, domain }, resolver) {
  const r = resolver || buildResolver(null, { timeout: 5000, tries: 2 });
  const z = ALL_ZONES.find((x) => x.zone === zone);
  const checks = [];

  // 1. Is it even still listed? It may have cleared since the last check.
  let stillListed = null;
  if (z && subject) {
    const q = await queryZone(z.type === 'ip' ? reverseIp(subject) : subject, z, r);
    stillListed = q.listed === true;
    checks.push({
      label: 'Still listed right now',
      ok: stillListed === false,
      required: false,
      detail: stillListed === false
        ? 'The entry is already gone. Nothing to submit.'
        : stillListed === true ? 'Yes, the entry is still there.' : 'The list did not answer.',
    });
  }

  // 2. Reverse DNS, forward confirmed. Most IP lists refuse removal without it.
  let ptrHost = null;
  if (isIp(subject)) {
    let fcrdns = false;
    try {
      const names = await r.reverse(subject);
      ptrHost = names[0] || null;
      if (ptrHost) {
        try { fcrdns = (await r.resolve4(ptrHost)).includes(subject); } catch { /* no forward */ }
      }
    } catch { /* no PTR */ }
    checks.push({
      label: 'Reverse DNS (PTR) exists',
      ok: Boolean(ptrHost),
      required: true,
      detail: ptrHost || 'No PTR record. Ask your host or cloud provider to set one.',
    });
    checks.push({
      label: 'PTR resolves back to this IP (FCrDNS)',
      ok: fcrdns,
      required: true,
      detail: fcrdns ? 'Confirmed.' : 'The PTR name does not resolve back to the IP. Several lists reject removal for this alone.',
    });
  }

  // 3. Can the list reach you? Confirmations go to postmaster@ or abuse@.
  const mailDomain = domain || (ptrHost ? ptrHost.split('.').slice(-2).join('.') : null);
  if (mailDomain) {
    let mx = [];
    try { mx = await r.resolveMx(mailDomain); } catch { /* none */ }
    checks.push({
      label: `${mailDomain} can receive mail`,
      ok: mx.length > 0,
      required: true,
      detail: mx.length
        ? `MX: ${mx.sort((a, b) => a.priority - b.priority)[0].exchange}. Make sure postmaster@ and abuse@ are delivered.`
        : 'No MX record, so the list cannot send you a confirmation.',
    });
  }

  // 4. SPF and DMARC. Not always mandatory, but a missing SPF gets requests
  //    rejected on the stricter lists and invites a new listing.
  if (mailDomain) {
    const txt = async (n) => { try { return (await r.resolveTxt(n)).map((x) => x.join('')); } catch { return []; } };
    const spf = (await txt(mailDomain)).find((t) => /^v=spf1\b/i.test(t.trim()));
    const dmarc = (await txt(`_dmarc.${mailDomain}`)).find((t) => /^v=DMARC1\b/i.test(t.trim()));
    checks.push({ label: 'SPF published', ok: Boolean(spf), required: false, detail: spf || 'No SPF record.' });
    checks.push({ label: 'DMARC published', ok: Boolean(dmarc), required: false, detail: dmarc || 'No DMARC record.' });
  }

  const ready = checks.filter((c) => c.required).every((c) => c.ok);
  return {
    zone,
    subject,
    stillListed,
    autoClears: AUTO_CLEARING[zone] || null,
    prefillUrl: prefillUrl(zone, subject),
    ready,
    checks,
  };
}

/** Is this entry still on the list? Used to poll after a request is sent. */
export async function stillListed(zone, subject, resolver) {
  const z = ALL_ZONES.find((x) => x.zone === zone);
  if (!z || !subject) return null;
  const r = resolver || buildResolver(null, { timeout: 5000, tries: 2 });
  const q = await queryZone(z.type === 'ip' ? reverseIp(subject) : subject, z, r);
  if (q.listed === null) return null;
  return q.listed === true && isListedAnswer(z, q.codes || []);
}
