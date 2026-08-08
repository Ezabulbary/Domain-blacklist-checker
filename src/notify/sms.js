import { ALL_ZONES } from '../lib/zones.js';

// SMS notifications for clients.
//
// An SMS is not a small email. Two constraints drive everything here:
//
//   1. Length. A GSM-7 message is 160 characters in one segment, and 153 per
//      segment once it splits. A single character outside GSM-7 (a curly quote,
//      a middle dot, any Bangla text) switches the whole message to UCS-2, where
//      a segment is 70 characters. So one stray character can triple the cost of
//      every message sent to 10,000 clients. renderSms() refuses to emit
//      anything that is not GSM-7, and keeps every message to one segment.
//
//   2. Attention. The client cannot act on a blocklist name in a phone
//      notification. The message says what broke, how urgent it is, and gives
//      one link. Detail belongs on the other end of that link.
//
// Which listings are worth an SMS at all is a judgement about real delivery
// impact, not something derivable from the score weight, so it is written down
// explicitly below.

// Lists that actually block mail at real receivers. A listing here is worth
// waking someone up for.
const TIER_1 = new Set([
  'zen.spamhaus.org',        // used by nearly every corporate and self-hosted server
  'dbl.spamhaus.org',        // domain reputation, changing IP does not help
  'b.barracudacentral.org',  // heavy in corporate environments
  'multi.surbl.org',         // blocks on links inside the mail, not the sending IP
]);

// Real, but confined to particular filters or ISPs. Worth a message, not a siren.
const TIER_2 = new Set([
  'combined.mail.abusix.zone', 'exploit.mail.abusix.zone', 'dblack.mail.abusix.zone',
  'sip.invaluement.com', 'uri.invaluement.com', 'sip24.invaluement.com',
  'uribl.spameatingmonkey.net', 'bl.mailspike.net', 'z.mailspike.net',
  'bl.score.senderscore.com', 'hostkarma.junkemailfilter.com', 'truncate.gbudb.net',
  // SpamCop auto-expires in about a day. Real, worth a calm message, not a
  // middle-of-the-night one.
  'bl.spamcop.net',
]);

// Lists that cause no delivery impact worth texting about: they list whole
// network ranges or entire ASNs, they are aggressive enough to list major
// legitimate domains, or no significant receiver consults them. These belong on
// the dashboard, never on someone's phone at night.
const NO_SMS = new Set([
  'dnsbl-2.uceprotect.net',  // lists your whole network range
  'dnsbl-3.uceprotect.net',  // lists an entire ASN. Gmail and Microsoft ignore it
  'dnsbl.zapbl.net', 'rhsbl.zapbl.net', // lists microsoft.com, github.com, nytimes.com
  'tor.dan.me.uk', 'torexit.dan.me.uk', // irrelevant unless you run a Tor exit
  'ips.backscatterer.org', 'backscatter.spameatingmonkey.net',
]);

/**
 * How urgently a listing on this zone should reach the client.
 * 'urgent' -> SMS now.  'normal' -> SMS now, calmer wording.
 * 'digest' -> daily summary only.  'none' -> dashboard only.
 */
export function smsTier(zone) {
  if (NO_SMS.has(zone)) return 'none';
  if (TIER_1.has(zone)) return 'urgent';
  if (TIER_2.has(zone)) return 'normal';
  const z = ALL_ZONES.find((x) => x.zone === zone);
  if (!z || z.status === 'defunct') return 'none';
  return 'digest';
}

// GSM-7 default alphabet, plus the extension table (those cost 2 characters).
const GSM7 = '@£$¥èéùìòÇ\nØø\rÅå'
  + 'Δ_ΦΓΛΩΠΨΣΘΞÆæßÉ'
  + ' !"#¤%&\'()*+,-./0123456789:;<=>?¡'
  + 'ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿'
  + 'abcdefghijklmnopqrstuvwxyzäöñüà';
const GSM7_EXT = '^{}\\[~]|€';

/** Character count, encoding and segment count for a message body. */
export function measure(text) {
  const chars = [...text];
  const gsm = chars.every((c) => GSM7.includes(c) || GSM7_EXT.includes(c));
  const length = gsm ? chars.reduce((n, c) => n + (GSM7_EXT.includes(c) ? 2 : 1), 0) : chars.length;
  const single = gsm ? 160 : 70;
  const multi = gsm ? 153 : 67;
  return { gsm, length, segments: length <= single ? 1 : Math.ceil(length / multi) };
}

const SINGLE_SEGMENT = 160;

// A 60-character domain would push any message past one segment, so shorten it
// in the middle and keep both ends, which is what a person needs to recognise it.
function fitDomain(domain, budget) {
  if (domain.length <= budget) return domain;
  if (budget < 9) return domain.slice(0, Math.max(1, budget));
  const head = Math.ceil((budget - 3) / 2);
  const tail = budget - 3 - head;
  return domain.slice(0, head) + '...' + domain.slice(domain.length - tail);
}

const listName = (zone) => (ALL_ZONES.find((z) => z.zone === zone) || {}).name || zone;

/**
 * Render the SMS body for one notification event.
 *
 * @param {object} e
 *   kind      'listed' | 'cleared' | 'multi' | 'digest' | 'reminder'
 *   brand     short sender label, e.g. 'Acme'
 *   domain    the affected domain (single-domain kinds)
 *   zone      the blocklist zone (single-domain kinds)
 *   extra     how many further lists beyond `zone` (optional)
 *   domains   how many domains affected (kind 'multi')
 *   urgent    how many of those are Tier 1 (kind 'multi')
 *   checked   domains checked today (kind 'digest')
 *   listings  low risk listings today (kind 'digest')
 *   days      days still listed (kind 'reminder')
 *   url       short link to the detail page
 * @returns {{ text, segments, length, gsm, tier }}
 */
export function renderSms(e) {
  const brand = e.brand ? `[${e.brand}] ` : '';
  const url = e.url ? ` ${e.url}` : '';
  const list = e.zone ? listName(e.zone) : '';
  const tier = e.zone ? smsTier(e.zone) : 'normal';
  const also = e.extra > 0 ? ` and ${e.extra} more list${e.extra > 1 ? 's' : ''}` : '';

  // Everything except the domain is fixed, so the domain gets whatever is left.
  const build = (d) => {
    switch (e.kind) {
      case 'cleared':
        return `${brand}Good news: ${d} has been removed from ${list}. Email delivery is back to normal. No action needed.`;
      case 'reminder':
        return `${brand}Reminder: ${d} is still blacklisted on ${list} after ${e.days} days. This needs action today:${url}`;
      case 'multi':
        return `${brand}Alert: ${e.domains} of your domains were blacklisted today, ${e.urgent} high risk. Full list and next steps:${url}`;
      case 'digest':
        return `${brand}Daily summary: ${e.checked} domains checked, ${e.listings} low risk listings, no delivery impact. Details:${url}`;
      case 'listed':
      default:
        return tier === 'urgent'
          ? `${brand}URGENT: ${d} is blacklisted on ${list}${also}. Your email is being blocked right now. Details and fix:${url}`
          : `${brand}Alert: ${d} was listed on ${list}${also}. Some mail may be rejected. We are on it. Details:${url}`;
    }
  };

  let text = build(e.domain || '');
  if (e.domain && measure(text).length > SINGLE_SEGMENT) {
    // Give the domain exactly the room that is left over.
    const overhead = measure(build('')).length;
    text = build(fitDomain(e.domain, Math.max(1, SINGLE_SEGMENT - overhead)));
  }

  const m = measure(text);
  if (!m.gsm) {
    // Non-GSM characters triple the cost of every message. Fail loudly in
    // development rather than quietly send UCS-2 to ten thousand people.
    throw new Error('SMS body is not GSM-7 encodable, which would triple send cost');
  }
  return { text, tier, ...m };
}
