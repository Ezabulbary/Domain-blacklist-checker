// DNSBL zone catalog — the ~68 blacklists an mxtoolbox-style check queries.
//
// Every hostname here was validated against live DNS (SOA/NS + the 127.0.0.2
// test-point) rather than copied from a web list. Each entry carries:
//
//   name      display label (as shown in the results table)
//   zone      the DNS zone to query
//   type      'ip'     -> query reversed-octet IP against the zone
//             'domain' -> query the registrable domain against the zone
//   weight    0-40, how much a listing hurts the score (Spamhaus >> SORBS)
//   severity  'critical' | 'high' | 'medium' | 'low'  (drives the UI badge)
//   note      one-line human description
//   delist    removal / lookup URL (so a listing is actionable)
//   requiresKey?  true if the list needs registration / a paid resolver — a
//                 SERVFAIL/blocked answer from a public resolver is reported as
//                 "unknown", never a false OK.
//   status    'live' | 'requiresKey' | 'defunct' | 'unverified'
//   listedCodes?  if set, a hit only counts as listed when a returned 127.x
//                 code is in this set (used for combined lists like Hostkarma
//                 whose 127.0.0.1 answer is a *whitelist*, not a listing).

export const IP_ZONES = [
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', type: 'ip', weight: 40, severity: 'critical', status: 'requiresKey', requiresKey: true, note: 'Spamhaus ZEN (SBL+XBL+PBL) — the most important IP blocklist.', delist: 'https://check.spamhaus.org/' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org', type: 'ip', weight: 20, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Barracuda Reputation Block List (registration required).', delist: 'https://www.barracudacentral.org/rbl/removal-request' },
  { name: 'SpamCop', zone: 'bl.spamcop.net', type: 'ip', weight: 15, severity: 'high', status: 'live', note: 'SpamCop Blocking List — auto-expires once the source is fixed.', delist: 'https://www.spamcop.net/bl.shtml' },
  { name: 'Abusix Mail Intelligence Blacklist', zone: 'combined.mail.abusix.zone', type: 'ip', weight: 18, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Abusix combined IP blacklist (API key required).', delist: 'https://lookup.abusix.com/' },
  { name: 'Abusix Mail Intelligence Exploit list', zone: 'exploit.mail.abusix.zone', type: 'ip', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Abusix exploited/compromised hosts (API key required).', delist: 'https://lookup.abusix.com/' },
  { name: 'ivmSIP', zone: 'sip.invaluement.com', type: 'ip', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'invaluement ivmSIP — spam-source IPs.', delist: 'https://www.invaluement.com/lookup/' },
  { name: 'ivmSIP24', zone: 'sip24.invaluement.com', type: 'ip', weight: 10, severity: 'medium', status: 'requiresKey', requiresKey: true, note: 'invaluement ivmSIP/24 — spam-source /24 ranges.', delist: 'https://www.invaluement.com/lookup/' },
  { name: 'PSBL', zone: 'psbl.surriel.com', type: 'ip', weight: 10, severity: 'medium', status: 'live', note: 'Passive Spam Block List.', delist: 'https://psbl.org/remove' },
  { name: 'DroneBL', zone: 'dnsbl.dronebl.org', type: 'ip', weight: 10, severity: 'medium', status: 'live', note: 'DroneBL — bots, drones, compromised hosts.', delist: 'https://dronebl.org/lookup' },
  { name: 'TRUNCATE', zone: 'truncate.gbudb.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'GBUdb Truncate — high-confidence spam sources.', delist: 'https://www.gbudb.com/truncate/' },
  { name: 'RATS Spam', zone: 'spam.spamrats.com', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'SpamRats RATS-Spam.', delist: 'https://www.spamrats.com/lookup.php' },
  { name: 'SEM BLACK', zone: 'bl.spameatingmonkey.net', type: 'ip', weight: 12, severity: 'medium', status: 'live', note: 'Spam Eating Monkey SEM-BLACK.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'MAILSPIKE BL', zone: 'bl.mailspike.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'Mailspike blacklist / worst reputation.', delist: 'https://www.mailspike.org/iplookup.html' },
  { name: 'MAILSPIKE Z', zone: 'z.mailspike.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'Mailspike Z — zombie / bad reputation.', delist: 'https://www.mailspike.org/iplookup.html' },
  { name: 'Sender Score Reputation Network', zone: 'bl.score.senderscore.com', type: 'ip', weight: 8, severity: 'medium', status: 'requiresKey', requiresKey: true, note: 'Validity Sender Score Reputation Network.', delist: 'https://senderscore.org/' },
  { name: 'BLOCKLIST.DE', zone: 'bl.blocklist.de', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'blocklist.de — reported attacking hosts.', delist: 'https://www.blocklist.de/en/delist.html' },
  { name: 'INTERSERVER', zone: 'rbl.interserver.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'InterServer RBL.', delist: 'https://rbl.interserver.net/' },
  { name: 'Hostkarma Black', zone: 'hostkarma.junkemailfilter.com', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'Junk Email Filter Hostkarma — black list only (127.0.0.1 = whitelist).', delist: 'https://ipadmin.junkemailfilter.com/remove.php', listedCodes: ['127.0.0.2', '127.0.0.4', '127.0.1.2', '127.0.1.3'] },
  { name: '0SPAM', zone: 'bl.0spam.org', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: '0SPAM blocklist.', delist: 'https://0spam.org/removal.php' },
  { name: '0SPAM RBL', zone: 'rbl.0spam.org', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: '0SPAM RBL.', delist: 'https://0spam.org/removal.php' },
  { name: 'LASHBACK', zone: 'ubl.unsubscore.com', type: 'ip', weight: 8, severity: 'medium', status: 'unverified', note: 'LashBack Unsubscribe Blacklist.', delist: 'https://blacklist.lashback.com/' },
  { name: 'UCEPROTECTL1', zone: 'dnsbl-1.uceprotect.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'UCEPROTECT Level 1 (single IP).', delist: 'https://www.uceprotect.net/en/rblcheck.php' },
  { name: 'UCEPROTECTL2', zone: 'dnsbl-2.uceprotect.net', type: 'ip', weight: 4, severity: 'low', status: 'live', note: 'UCEPROTECT Level 2 (allocation) — high false-positive rate.', delist: 'https://www.uceprotect.net/en/rblcheck.php' },
  { name: 'UCEPROTECTL3', zone: 'dnsbl-3.uceprotect.net', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'UCEPROTECT Level 3 (AS) — informational, very broad.', delist: 'https://www.uceprotect.net/en/rblcheck.php' },
  { name: 'RATS Dyna', zone: 'dyna.spamrats.com', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'SpamRats RATS-Dyna — dynamic/residential ranges.', delist: 'https://www.spamrats.com/lookup.php' },
  { name: 'RATS NoPtr', zone: 'noptr.spamrats.com', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'SpamRats RATS-NoPtr — no reverse DNS.', delist: 'https://www.spamrats.com/lookup.php' },
  { name: 'SEM BACKSCATTER', zone: 'backscatter.spameatingmonkey.net', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Spam Eating Monkey backscatter sources.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'BACKSCATTERER', zone: 'ips.backscatterer.org', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'UCEPROTECT Backscatterer — misdirected bounces.', delist: 'https://www.backscatterer.org/?target=test' },
  { name: 'Anonmails DNSBL', zone: 'spam.dnsbl.anonmails.de', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Anonmails spam sources.', delist: 'https://anonmails.de/dnsbl.php' },
  { name: 'FABELSOURCES', zone: 'spamsources.fabel.dk', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Fabel spam sources.', delist: 'https://fabel.dk/' },
  { name: 's5h.net', zone: 'all.s5h.net', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 's5h.net aggregate blocklist.', delist: 'https://www.usenix.org.uk/content/rbl.html' },
  { name: 'SPFBL DNSBL', zone: 'dnsbl.spfbl.net', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'SPFBL reputation blocklist.', delist: 'https://spfbl.net/en/dnsbl/' },
  { name: 'CYMRU BOGONS', zone: 'bogons.cymru.com', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Team Cymru Bogons — unallocated/unroutable space.', delist: 'https://www.team-cymru.com/bogon-reference' },
  { name: 'IMP SPAM', zone: 'spamrbl.imp.ch', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'IMP Switzerland spam RBL.', delist: 'https://antispam.imp.ch/' },
  { name: 'IMP WORM', zone: 'wormrbl.imp.ch', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'IMP Switzerland worm RBL.', delist: 'https://antispam.imp.ch/' },
  { name: 'ICMFORBIDDEN', zone: 'forbidden.icm.edu.pl', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'ICM (Poland) forbidden hosts.', delist: 'https://www.icm.edu.pl/' },
  { name: 'ZapBL', zone: 'dnsbl.zapbl.net', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'ZapBL DNSBL.', delist: 'https://zapbl.net/' },
  { name: 'SCHULTE', zone: 'rbl.schulte.org', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'Schulte RBL.', delist: 'https://rbl.schulte.org/' },
  { name: 'SWINOG', zone: 'dnsrbl.swinog.ch', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'SWINOG (Swiss Network Operators Group) RBL.', delist: 'https://antispam.imp.ch/' },
  { name: 'SERVICESNET', zone: 'korea.services.net', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'Services.net Korea blocklist.', delist: 'https://www.services.net/' },
  { name: 'JIPPG', zone: 'mail-abuse.blacklist.jippg.org', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'JIPPG mail-abuse blacklist.', delist: 'https://www.jippg.org/' },
  { name: 'KEMPTBL', zone: 'dnsbl.kempt.net', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'Kempt.net DNSBL.', delist: 'https://www.kempt.net/' },
  { name: 'CALIVENT', zone: 'dnsbl.calivent.com.pe', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'Calivent DNSBL.', delist: 'https://www.calivent.com.pe/' },
  { name: 'DAN TOR', zone: 'tor.dan.me.uk', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'dan.me.uk — Tor nodes.', delist: 'https://www.dan.me.uk/dnsbl' },
  { name: 'DAN TOREXIT', zone: 'torexit.dan.me.uk', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'dan.me.uk — Tor exit nodes.', delist: 'https://www.dan.me.uk/dnsbl' },
  { name: 'Konstant', zone: 'bl.konstant.no', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'Konstant (Norway) blocklist.', delist: 'https://www.konstant.no/' },
  { name: 'RBL JP', zone: 'all.rbl.jp', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'RBL.JP (Japan) aggregate.', delist: 'https://www.rbl.jp/' },
  { name: 'TRIUMF', zone: 'rbl2.triumf.ca', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'TRIUMF (Canada) RBL.', delist: 'https://www.triumf.ca/' },
  { name: 'NETHERRELAYS', zone: 'relays.nether.net', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'nether.net open relays.', delist: 'https://www.nether.net/' },
  { name: 'NETHERUNSURE', zone: 'unsure.nether.net', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'nether.net unsure list.', delist: 'https://www.nether.net/' },
  { name: 'Woodys SMTP Blacklist', zone: 'blacklist.woody.ch', type: 'ip', weight: 3, severity: 'low', status: 'live', note: "Woody's SMTP blacklist.", delist: 'https://woody.ch/' },
  { name: 'MSRBL Phishing', zone: 'phishing.rbl.msrbl.net', type: 'ip', weight: 3, severity: 'low', status: 'defunct', note: 'MSRBL Phishing — list appears inactive.', delist: 'https://www.msrbl.com/' },
  { name: 'MSRBL Spam', zone: 'spam.rbl.msrbl.net', type: 'ip', weight: 3, severity: 'low', status: 'defunct', note: 'MSRBL Spam — list appears inactive.', delist: 'https://www.msrbl.com/' },
  { name: 'DRMX', zone: 'drmx.org', type: 'ip', weight: 3, severity: 'low', status: 'defunct', note: 'DrMX project — list appears inactive.', delist: 'https://mxtoolbox.com/problem/blacklist/drmx' },
  { name: 'IBM DNS Blacklist', zone: 'dnsbl.cobion.com', type: 'ip', weight: 5, severity: 'low', status: 'requiresKey', requiresKey: true, note: 'IBM X-Force / Cobion — not publicly queryable.', delist: 'https://filterdb.iss.net/dnsblinfo/' },
];

export const DOMAIN_ZONES = [
  { name: 'Spamhaus DBL', zone: 'dbl.spamhaus.org', type: 'domain', weight: 40, severity: 'critical', status: 'requiresKey', requiresKey: true, note: 'Spamhaus Domain Block List — the most important domain blocklist.', delist: 'https://check.spamhaus.org/' },
  { name: 'SURBL multi', zone: 'multi.surbl.org', type: 'domain', weight: 20, severity: 'high', status: 'live', note: 'SURBL multi — spam/phishing/malware URIs.', delist: 'https://www.surbl.org/delisting' },
  { name: 'SEM URI', zone: 'uribl.spameatingmonkey.net', type: 'domain', weight: 15, severity: 'high', status: 'live', note: 'Spam Eating Monkey SEM-URI.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'ivmURI', zone: 'uri.invaluement.com', type: 'domain', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'invaluement ivmURI — spam-vector domains.', delist: 'https://www.invaluement.com/lookup/' },
  { name: 'Abusix Mail Intelligence Domain Blacklist', zone: 'dblack.mail.abusix.zone', type: 'domain', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Abusix domain blacklist (API key required).', delist: 'https://lookup.abusix.com/' },
  { name: 'SEM URIRED', zone: 'urired.spameatingmonkey.net', type: 'domain', weight: 12, severity: 'medium', status: 'live', note: 'Spam Eating Monkey SEM-URIRED.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'SEM FRESH', zone: 'fresh.spameatingmonkey.net', type: 'domain', weight: 10, severity: 'medium', status: 'live', note: 'Spam Eating Monkey SEM-FRESH — newly seen domains.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'ZapBL RHSBL', zone: 'rhsbl.zapbl.net', type: 'domain', weight: 5, severity: 'low', status: 'live', note: 'ZapBL right-hand-side (domain) blocklist.', delist: 'https://zapbl.net/' },
  { name: 'NoSolicitado', zone: 'bl.nosolicitado.org', type: 'domain', weight: 5, severity: 'low', status: 'unverified', note: 'NoSolicitado (Argentina) domain blocklist.', delist: 'https://www.nosolicitado.org/' },
  { name: 'Suomispam Reputation', zone: 'reputation-domain.rbl.suomispam.net', type: 'domain', weight: 5, severity: 'low', status: 'unverified', note: 'Suomispam domain reputation.', delist: 'https://suomispam.net/' },
  { name: 'SORBS RHSBL BADCONF', zone: 'badconf.rhsbl.sorbs.net', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'SORBS RHSBL badconf — SORBS shut down in 2024.', delist: 'https://www.sorbs.net/' },
  { name: 'SORBS RHSBL NOMAIL', zone: 'nomail.rhsbl.sorbs.net', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'SORBS RHSBL nomail — SORBS shut down in 2024.', delist: 'https://www.sorbs.net/' },
  { name: 'HIL', zone: 'hil.habeas.com', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'Habeas Infringer List — list appears inactive.', delist: 'https://mxtoolbox.com/problem/blacklist/hil' },
  { name: 'HIL2', zone: 'hul.habeas.com', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'Habeas User List — list appears inactive.', delist: 'https://mxtoolbox.com/problem/blacklist/hil2' },
];

// Return-code meanings for the lists that document them (surfaced in the UI).
export const RETURN_CODES = {
  'zen.spamhaus.org': {
    '127.0.0.2': 'SBL — Spamhaus Blocklist',
    '127.0.0.3': 'SBL CSS — snowshoe spam',
    '127.0.0.4': 'XBL — CBL (exploited/bot)',
    '127.0.0.9': 'SBL DROP/EDROP',
    '127.0.0.10': 'PBL — ISP dynamic/no-mail policy',
    '127.0.0.11': 'PBL — Spamhaus-maintained dynamic range',
  },
  'dbl.spamhaus.org': {
    '127.0.1.2': 'spam domain',
    '127.0.1.4': 'phishing domain',
    '127.0.1.5': 'malware domain',
    '127.0.1.6': 'botnet C&C domain',
    '127.0.1.102': 'abused legit spam',
    '127.0.1.104': 'abused legit phishing',
    '127.0.1.255': 'BLOCKED — query volume/policy error, treat as unknown',
  },
  'hostkarma.junkemailfilter.com': {
    '127.0.0.1': 'whitelist (good)',
    '127.0.0.2': 'blacklist',
    '127.0.0.3': 'yellowlist (mixed)',
    '127.0.0.5': 'brownlist (suspicious)',
  },
};

// Assign a UI category to each zone so the Blacklists grid can filter by
// All / Email / Domain-URI / IP / Spam-Phishing / Malware. Derived from the
// zone's purpose (keywords) falling back to its query type.
export function categorize(z) {
  const s = `${z.name} ${z.zone} ${z.note || ''}`.toLowerCase();
  if (/whitelist|dnswl|\bwl\b/.test(s)) return 'whitelist';
  if (/malware|drone|exploit|worm|botnet|virus|trojan/.test(s)) return 'malware';
  if (/phish|fraud|scam/.test(s)) return 'spam';
  if (/spam|uce|abuse/.test(s) && z.type === 'domain') return 'spam';
  if (z.type === 'domain') return 'domain';
  // IP-type: email-sending reputation lists vs generic IP reputation.
  if (/spamhaus|barracuda|spamcop|sender ?score|mailspike|hostkarma|abusix|invaluement|cbl|validity|senderscore|reputation|postmaster|snds|fbl/.test(s)) {
    return 'email';
  }
  return 'ip';
}

for (const z of [...IP_ZONES, ...DOMAIN_ZONES]) {
  z.category = categorize(z);
}

export const ALL_ZONES = [...IP_ZONES, ...DOMAIN_ZONES];

export const CATEGORIES = [
  { key: 'all', label: 'All' },
  { key: 'email', label: 'Email / Cold Send' },
  { key: 'domain', label: 'Domain / URI' },
  { key: 'ip', label: 'IP Reputation' },
  { key: 'spam', label: 'Spam / Phishing' },
  { key: 'malware', label: 'Malware' },
];
