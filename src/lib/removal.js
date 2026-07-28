// Removal guidance: what to actually do when a blocklist lists you.
//
// A link alone is not much help, because most lists relist you within hours if
// the cause is still there. So every entry carries: what the listing means, the
// steps in order, and whether removal is automatic, self-service or paid.
//
//   kind: 'auto'  expires by itself once the cause stops
//         'self'  you submit a removal request yourself
//         'paid'  free removal is limited or slow, express removal costs money
//         'isp'   the listing covers a whole range, your provider must act

// Applies to every listing. Doing this first is what makes removal stick.
export const COMMON_STEPS = [
  'Find and stop the cause first. A compromised mailbox, a script sending through your server, an open relay or a purchased list are the usual ones. If you skip this you will be listed again within hours.',
  'Check that the sending IP has valid reverse DNS (PTR) and that the name resolves back to the same IP. Many lists refuse removal without it.',
  'Make sure SPF, DKIM and DMARC pass for your domain. See the Email auth tab.',
  'Make sure abuse@ and postmaster@ for your domain actually receive mail. Several lists send the confirmation there.',
];

const GUIDES = {
  'dnsbl.spfbl.net': {
    kind: 'self',
    means: 'SPFBL saw spam or a bad reputation score from this IP.',
    steps: [
      'Open the SPFBL delist page and enter the IP.',
      'Free removal requires: valid FCrDNS (the PTR resolves back to the same IP) on a domain you own, a paid TLD with public WHOIS (no privacy shield), a working postmaster@ address on that domain, and a reputation score with under 25 percent negative points.',
      'If your setup meets that, the removal is instant. If not, SPFBL offers a paid delisting instead.',
    ],
  },
  'zen.spamhaus.org': {
    kind: 'self',
    means: 'Spamhaus ZEN combines SBL (spam source), XBL (compromised or infected host) and PBL (an IP your provider says should not send mail directly).',
    steps: [
      'Look the IP up on the Spamhaus Blocklist Removal Center to see which of the three lists it is on. The fix depends on that.',
      'PBL: this is normal for home and dynamic IPs. Send through your provider or your mail host instead, or ask your provider to change the policy for the IP.',
      'XBL: the host is infected or relaying. Clean it, close the relay, then request removal.',
      'SBL: read the SBL record, fix what it names, then use the removal form.',
    ],
  },
  'dbl.spamhaus.org': {
    kind: 'self',
    means: 'The domain itself (not just the IP) was seen in spam, phishing or malware.',
    steps: [
      'Look the domain up on the Spamhaus removal centre to see the reason code.',
      'If the domain was compromised, clean the site and remove any injected redirects before asking for removal.',
      'Submit the removal request. Spamhaus normally reviews domain removals quickly.',
    ],
  },
  'multi.surbl.org': {
    kind: 'self',
    means: 'The domain appeared inside spam or phishing messages, so mail mentioning it gets blocked.',
    steps: [
      'Check the domain on the SURBL lookup to see which sublist it is on (phishing, malware, abuse).',
      'If your site was hacked or hosts a redirect, clean it first. SURBL rechecks before removing.',
      'Submit the removal request from the SURBL removal page.',
    ],
  },
  'dnsbl-1.uceprotect.net': {
    kind: 'auto',
    means: 'A single IP was seen sending to a UCEPROTECT trap in the last 7 days.',
    steps: [
      'Stop the sending that caused it.',
      'Level 1 expires on its own 7 days after the last event. Just waiting is the normal fix.',
      'UCEPROTECT also sells an express removal. It is not required, and paying does not prevent a new listing.',
    ],
  },
  'dnsbl-2.uceprotect.net': {
    kind: 'isp',
    means: 'This lists a whole allocation, not your IP alone. A neighbour on your provider network triggered it.',
    steps: [
      'You usually cannot fix this yourself, your own IP may be clean.',
      'Ask your hosting provider or ISP to deal with the abuse in their range.',
      'Most receivers do not use Level 2 or 3 for blocking because they are so broad. Treat it as low priority.',
    ],
  },
  'dnsbl-3.uceprotect.net': {
    kind: 'isp',
    means: 'This lists an entire autonomous system (your provider network), not your server.',
    steps: [
      'Nothing on your server causes or fixes this.',
      'If it matters for your mail flow, move to a provider with a cleaner network.',
      'Very few receivers block on Level 3. Usually safe to ignore.',
    ],
  },
  'b.barracudacentral.org': {
    kind: 'self',
    means: 'Barracuda scored the IP as a spam source.',
    steps: [
      'Stop the source of the spam and confirm the IP has valid reverse DNS.',
      'Fill in the Barracuda removal request form with a working contact address.',
      'Removal is usually processed within about 12 hours.',
    ],
  },
  'bl.spamcop.net': {
    kind: 'auto',
    means: 'SpamCop received spam reports or trap hits from this IP.',
    steps: [
      'Stop the sending that generated the reports.',
      'SpamCop listings expire automatically, usually within 24 hours of the last report.',
      'You can also request an immediate delisting from the SpamCop lookup page once the cause is fixed.',
    ],
  },
  'psbl.surriel.com': {
    kind: 'auto',
    means: 'The IP hit a PSBL spam trap.',
    steps: [
      'Stop the sending that hit the trap.',
      'Use the PSBL removal page. Removal is self-service and immediate.',
      'The listing also expires on its own if no further spam is seen.',
    ],
  },
  'bl.mailspike.net': {
    kind: 'self',
    means: 'Mailspike scored the IP as having a bad sending reputation.',
    steps: [
      'Fix the sending behaviour, in particular bounce and complaint rates.',
      'Use the Mailspike lookup page and submit a reputation review for the IP.',
    ],
  },
  'bl.blocklist.de': {
    kind: 'auto',
    means: 'The IP was reported for attacks such as SSH or mail brute force, not necessarily spam.',
    steps: [
      'Check the server for a compromise or a misconfigured service. This listing usually means something on the host is attacking others.',
      'Use the blocklist.de delist form once the host is clean.',
      'Entries also expire automatically after roughly 48 hours without new reports.',
    ],
  },
  'dnsbl.dronebl.org': {
    kind: 'self',
    means: 'DroneBL sees the IP as a bot, a proxy or a compromised host.',
    steps: [
      'Scan and clean the host, and close any open proxy or relay.',
      'Submit a removal request from the DroneBL lookup page.',
    ],
  },
  'ips.backscatterer.org': {
    kind: 'auto',
    means: 'Your server sent bounces or auto-replies to forged senders (backscatter).',
    steps: [
      'Stop accepting mail for unknown recipients and then bouncing it. Reject at SMTP time instead.',
      'Turn off auto-replies and out-of-office to unauthenticated senders.',
      'The listing expires by itself once the backscatter stops.',
    ],
  },
  'truncate.gbudb.net': {
    kind: 'auto',
    means: 'GBUdb sees a very high spam ratio from this IP.',
    steps: [
      'Stop the spam source.',
      'Truncate entries clear automatically as the IP sends normal mail again. There is no form to fill in.',
    ],
  },
  'rbl.interserver.net': {
    kind: 'self',
    means: 'InterServer detected spam from the IP.',
    steps: [
      'Fix the source, then use the InterServer removal page to request delisting.',
    ],
  },
  'bl.0spam.org': {
    kind: 'self',
    means: 'The IP hit a 0SPAM trap.',
    steps: ['Stop the sending, then use the 0SPAM removal form.'],
  },
  'bl.spameatingmonkey.net': {
    kind: 'self',
    means: 'Spam Eating Monkey saw spam from this IP.',
    steps: ['Fix the source, then request removal from the SEM lookup page.'],
  },
};

/**
 * Removal guidance for one listing.
 * Returns { kind, means, steps, common, url }.
 */
export function removalGuide(row) {
  const g = GUIDES[row.zone];
  return {
    zone: row.zone,
    name: row.name,
    subject: row.subject,
    kind: g ? g.kind : 'self',
    means: g ? g.means : `${row.name} lists this ${row.type === 'ip' ? 'IP address' : 'domain'} as a source of unwanted mail.`,
    steps: g ? g.steps : [
      'Open the removal page for this list and look up the entry to see the stated reason.',
      'Fix what it names, then submit the removal request from the same page.',
    ],
    common: COMMON_STEPS,
    url: row.delist || null,
  };
}

export const KIND_LABEL = {
  auto: 'Clears automatically',
  self: 'You request removal',
  paid: 'Free removal is limited',
  isp: 'Your provider must act',
};
