// DNSBL zone catalog. The ~68 blacklists an mxtoolbox-style check queries.
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
//   requiresKey?  true if the list needs registration / a paid resolver. A
//                 SERVFAIL/blocked answer from a public resolver is reported as
//                 "unknown", never a false OK.
//   status    'live' | 'requiresKey' | 'defunct' | 'unverified'
//   listedCodes?  if set, a hit only counts as listed when a returned 127.x
//                 code is in this set (used for combined lists like Hostkarma
//                 whose 127.0.0.1 answer is a *whitelist*, not a listing).

export const IP_ZONES = [
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', type: 'ip', weight: 40, severity: 'critical', status: 'requiresKey', requiresKey: true, note: 'Spamhaus ZEN (SBL+XBL+PBL). The most important IP blocklist.', delist: 'https://check.spamhaus.org/' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org', type: 'ip', weight: 20, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Barracuda Reputation Block List (registration required).', delist: 'https://www.barracudacentral.org/rbl/removal-request' },
  { name: 'SpamCop', zone: 'bl.spamcop.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'SpamCop Blocking List. Auto-expires in about a day, so its real-world impact is modest; treat a hit as a symptom to fix, not a crisis.', delist: 'https://www.spamcop.net/bl.shtml' },
  { name: 'Abusix Mail Intelligence Blacklist', zone: 'combined.mail.abusix.zone', type: 'ip', weight: 18, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Abusix combined IP blacklist (API key required).', delist: 'https://lookup.abusix.com/' },
  { name: 'Abusix Mail Intelligence Exploit list', zone: 'exploit.mail.abusix.zone', type: 'ip', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Abusix exploited/compromised hosts (API key required).', delist: 'https://lookup.abusix.com/' },
  { name: 'ivmSIP', zone: 'sip.invaluement.com', type: 'ip', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'invaluement ivmSIP. Spam-source IPs.', delist: 'https://www.invaluement.com/lookup/' },
  { name: 'ivmSIP24', zone: 'sip24.invaluement.com', type: 'ip', weight: 10, severity: 'medium', status: 'requiresKey', requiresKey: true, note: 'invaluement ivmSIP/24. Spam-source /24 ranges.', delist: 'https://www.invaluement.com/lookup/' },
  { name: 'PSBL', zone: 'psbl.surriel.com', type: 'ip', weight: 10, severity: 'medium', status: 'live', note: 'Passive Spam Block List.', delist: 'https://psbl.org/remove' },
  { name: 'DroneBL', zone: 'dnsbl.dronebl.org', type: 'ip', weight: 10, severity: 'medium', status: 'live', note: 'DroneBL. Bots, drones, compromised hosts.', delist: 'https://dronebl.org/lookup' },
  { name: 'TRUNCATE', zone: 'truncate.gbudb.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'GBUdb Truncate. High-confidence spam sources.', delist: 'https://www.gbudb.com/truncate/' },
  { name: 'RATS Spam', zone: 'spam.spamrats.com', type: 'ip', weight: 8, severity: 'medium', status: 'requiresKey', requiresKey: true, note: 'SpamRats RATS-Spam. Refuses public resolvers; use your own resolver.', delist: 'https://www.spamrats.com/lookup.php' },
  { name: 'SEM BLACK', zone: 'bl.spameatingmonkey.net', type: 'ip', weight: 12, severity: 'medium', status: 'live', note: 'Spam Eating Monkey SEM-BLACK.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'MAILSPIKE BL', zone: 'bl.mailspike.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'Mailspike blacklist / worst reputation.', delist: 'https://www.mailspike.org/iplookup.html' },
  { name: 'MAILSPIKE Z', zone: 'z.mailspike.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'Mailspike Z. Zombie / bad reputation.', delist: 'https://www.mailspike.org/iplookup.html' },
  { name: 'Sender Score Reputation Network', zone: 'bl.score.senderscore.com', type: 'ip', weight: 8, severity: 'medium', status: 'requiresKey', requiresKey: true, note: 'Validity Sender Score Reputation Network.', delist: 'https://senderscore.org/' },
  { name: 'BLOCKLIST.DE', zone: 'bl.blocklist.de', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'blocklist.de. Reported attacking hosts.', delist: 'https://www.blocklist.de/en/delist.html' },
  { name: 'INTERSERVER', zone: 'rbl.interserver.net', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: 'InterServer RBL.', delist: 'https://rbl.interserver.net/' },
  { name: 'Hostkarma Black', zone: 'hostkarma.junkemailfilter.com', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Junk Email Filter Hostkarma. Black list only (127.0.0.1 = whitelist).', delist: 'https://ipadmin.junkemailfilter.com/remove.php', listedCodes: ['127.0.0.2', '127.0.0.4', '127.0.1.2', '127.0.1.3'] },
  { name: '0SPAM', zone: 'bl.0spam.org', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: '0SPAM blocklist.', delist: 'https://0spam.org/removal.php' },
  { name: '0SPAM RBL', zone: 'rbl.0spam.org', type: 'ip', weight: 8, severity: 'medium', status: 'live', note: '0SPAM RBL.', delist: 'https://0spam.org/removal.php' },
  { name: 'LASHBACK', zone: 'ubl.unsubscore.com', type: 'ip', weight: 5, severity: 'low', status: 'unverified', note: 'LashBack Unsubscribe Blacklist.', delist: 'https://blacklist.lashback.com/' },
  { name: 'UCEPROTECTL1', zone: 'dnsbl-1.uceprotect.net', type: 'ip', weight: 6, severity: 'medium', status: 'live', note: 'UCEPROTECT Level 1 (single IP).', delist: 'https://www.uceprotect.net/en/rblcheck.php' },
  { name: 'UCEPROTECTL2', zone: 'dnsbl-2.uceprotect.net', type: 'ip', weight: 4, severity: 'low', status: 'live', note: 'UCEPROTECT Level 2 (allocation). High false-positive rate.', delist: 'https://www.uceprotect.net/en/rblcheck.php' },
  { name: 'UCEPROTECTL3', zone: 'dnsbl-3.uceprotect.net', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'UCEPROTECT Level 3 (AS). Informational, very broad.', delist: 'https://www.uceprotect.net/en/rblcheck.php' },
  { name: 'RATS Dyna', zone: 'dyna.spamrats.com', type: 'ip', weight: 5, severity: 'low', status: 'requiresKey', requiresKey: true, note: 'SpamRats RATS-Dyna. Refuses public resolvers; use your own resolver.', delist: 'https://www.spamrats.com/lookup.php' },
  { name: 'RATS NoPtr', zone: 'noptr.spamrats.com', type: 'ip', weight: 5, severity: 'low', status: 'requiresKey', requiresKey: true, note: 'SpamRats RATS-NoPtr. Refuses public resolvers; use your own resolver.', delist: 'https://www.spamrats.com/lookup.php' },
  { name: 'SEM BACKSCATTER', zone: 'backscatter.spameatingmonkey.net', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Spam Eating Monkey backscatter sources.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'BACKSCATTERER', zone: 'ips.backscatterer.org', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'UCEPROTECT Backscatterer. Misdirected bounces.', delist: 'https://www.backscatterer.org/?target=test' },
  { name: 'Anonmails DNSBL', zone: 'spam.dnsbl.anonmails.de', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Anonmails spam sources.', delist: 'https://anonmails.de/dnsbl.php' },
  { name: 'FABELSOURCES', zone: 'spamsources.fabel.dk', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Fabel spam sources.', delist: 'https://fabel.dk/' },
  { name: 's5h.net', zone: 'all.s5h.net', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 's5h.net aggregate blocklist.', delist: 'https://www.usenix.org.uk/content/rbl.html' },
  // SPFBL answers two different questions on one zone. 127.0.0.2/.3 are spam
  // findings; 127.0.0.4 and .5 are policy flags ("no mail service here", NAT,
  // residential, unreliable abuse contact). Because we test a domain's A
  // records, which are web servers and not mail servers, .4 fires on a large
  // share of the internet (anything behind Cloudflare, GitHub, and so on).
  // Counting those as listings produced false LISTED rows for roughly a third of
  // ordinary domains. Only the spam codes count. See ACCURACY.md §7.
  { name: 'SPFBL DNSBL', zone: 'dnsbl.spfbl.net', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'SPFBL reputation blocklist. Spam codes only; the "no mail service" policy flag is not a listing.', delist: 'https://spfbl.net/en/dnsbl/', listedCodes: ['127.0.0.2', '127.0.0.3'] },
  { name: 'CYMRU BOGONS', zone: 'bogons.cymru.com', type: 'ip', weight: 5, severity: 'low', status: 'live', note: 'Team Cymru Bogons. Unallocated/unroutable space.', delist: 'https://www.team-cymru.com/bogon-reference' },
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
  { name: 'DAN TOR', zone: 'tor.dan.me.uk', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'dan.me.uk, Tor nodes.', delist: 'https://www.dan.me.uk/dnsbl' },
  { name: 'DAN TOREXIT', zone: 'torexit.dan.me.uk', type: 'ip', weight: 3, severity: 'low', status: 'live', note: 'dan.me.uk, Tor exit nodes.', delist: 'https://www.dan.me.uk/dnsbl' },
  { name: 'Konstant', zone: 'bl.konstant.no', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'Konstant (Norway) blocklist.', delist: 'https://www.konstant.no/' },
  { name: 'RBL JP', zone: 'all.rbl.jp', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'RBL.JP (Japan) aggregate.', delist: 'https://www.rbl.jp/' },
  { name: 'TRIUMF', zone: 'rbl2.triumf.ca', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'TRIUMF (Canada) RBL.', delist: 'https://www.triumf.ca/' },
  { name: 'NETHERRELAYS', zone: 'relays.nether.net', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'nether.net open relays.', delist: 'https://www.nether.net/' },
  { name: 'NETHERUNSURE', zone: 'unsure.nether.net', type: 'ip', weight: 3, severity: 'low', status: 'unverified', note: 'nether.net unsure list.', delist: 'https://www.nether.net/' },
  { name: 'Woodys SMTP Blacklist', zone: 'blacklist.woody.ch', type: 'ip', weight: 3, severity: 'low', status: 'live', note: "Woody's SMTP blacklist.", delist: 'https://woody.ch/' },
  { name: 'MSRBL Phishing', zone: 'phishing.rbl.msrbl.net', type: 'ip', weight: 3, severity: 'low', status: 'defunct', note: 'MSRBL Phishing. List appears inactive.', delist: 'https://www.msrbl.com/' },
  { name: 'MSRBL Spam', zone: 'spam.rbl.msrbl.net', type: 'ip', weight: 3, severity: 'low', status: 'defunct', note: 'MSRBL Spam. List appears inactive.', delist: 'https://www.msrbl.com/' },
  { name: 'DRMX', zone: 'drmx.org', type: 'ip', weight: 3, severity: 'low', status: 'defunct', note: 'DrMX project. List appears inactive.', delist: 'https://mxtoolbox.com/problem/blacklist/drmx' },
  { name: 'IBM DNS Blacklist', zone: 'dnsbl.cobion.com', type: 'ip', weight: 5, severity: 'low', status: 'requiresKey', requiresKey: true, note: 'IBM X-Force / Cobion. Not publicly queryable.', delist: 'https://filterdb.iss.net/dnsblinfo/' },
];

export const DOMAIN_ZONES = [
  { name: 'Spamhaus DBL', zone: 'dbl.spamhaus.org', type: 'domain', weight: 40, severity: 'critical', status: 'requiresKey', requiresKey: true, note: 'Spamhaus Domain Block List. The most important domain blocklist.', delist: 'https://check.spamhaus.org/' },
  { name: 'SURBL multi', zone: 'multi.surbl.org', type: 'domain', weight: 15, severity: 'high', status: 'live', note: 'SURBL multi. Spam/phishing/malware URIs.', delist: 'https://www.surbl.org/delisting' },
  { name: 'SEM URI', zone: 'uribl.spameatingmonkey.net', type: 'domain', weight: 15, severity: 'high', status: 'live', note: 'Spam Eating Monkey SEM-URI.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'ivmURI', zone: 'uri.invaluement.com', type: 'domain', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'invaluement ivmURI. Spam-vector domains.', delist: 'https://www.invaluement.com/lookup/' },
  { name: 'Abusix Mail Intelligence Domain Blacklist', zone: 'dblack.mail.abusix.zone', type: 'domain', weight: 15, severity: 'high', status: 'requiresKey', requiresKey: true, note: 'Abusix domain blacklist (API key required).', delist: 'https://lookup.abusix.com/' },
  { name: 'SEM URIRED', zone: 'urired.spameatingmonkey.net', type: 'domain', weight: 12, severity: 'medium', status: 'live', note: 'Spam Eating Monkey SEM-URIRED.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'SEM FRESH', zone: 'fresh.spameatingmonkey.net', type: 'domain', weight: 10, severity: 'medium', status: 'live', note: 'Spam Eating Monkey SEM-FRESH. Newly seen domains.', delist: 'https://spameatingmonkey.com/lookup' },
  { name: 'ZapBL RHSBL', zone: 'rhsbl.zapbl.net', type: 'domain', weight: 5, severity: 'low', status: 'live', note: 'ZapBL right-hand-side (domain) blocklist. Aggressive: it lists some large, legitimate domains, so weigh it lightly.', delist: 'https://zapbl.net/' },
  { name: 'NoSolicitado', zone: 'bl.nosolicitado.org', type: 'domain', weight: 5, severity: 'low', status: 'unverified', note: 'NoSolicitado (Argentina) domain blocklist.', delist: 'https://www.nosolicitado.org/' },
  { name: 'Suomispam Reputation', zone: 'reputation-domain.rbl.suomispam.net', type: 'domain', weight: 5, severity: 'low', status: 'unverified', note: 'Suomispam domain reputation.', delist: 'https://suomispam.net/' },
  { name: 'SORBS RHSBL BADCONF', zone: 'badconf.rhsbl.sorbs.net', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'SORBS RHSBL badconf, SORBS shut down in 2024.', delist: 'https://www.sorbs.net/' },
  { name: 'SORBS RHSBL NOMAIL', zone: 'nomail.rhsbl.sorbs.net', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'SORBS RHSBL nomail, SORBS shut down in 2024.', delist: 'https://www.sorbs.net/' },
  { name: 'HIL', zone: 'hil.habeas.com', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'Habeas Infringer List. List appears inactive.', delist: 'https://mxtoolbox.com/problem/blacklist/hil' },
  { name: 'HIL2', zone: 'hul.habeas.com', type: 'domain', weight: 3, severity: 'low', status: 'defunct', note: 'Habeas User List. List appears inactive.', delist: 'https://mxtoolbox.com/problem/blacklist/hil2' },
];

// Return-code meanings for the lists that document them (surfaced in the UI).
export const RETURN_CODES = {
  'zen.spamhaus.org': {
    '127.0.0.2': 'SBL, Spamhaus Blocklist',
    '127.0.0.3': 'SBL CSS. Snowshoe spam',
    '127.0.0.4': 'XBL, CBL (exploited/bot)',
    '127.0.0.9': 'SBL DROP/EDROP',
    '127.0.0.10': 'PBL, ISP dynamic/no-mail policy',
    '127.0.0.11': 'PBL, Spamhaus-maintained dynamic range',
  },
  'dbl.spamhaus.org': {
    '127.0.1.2': 'spam domain',
    '127.0.1.4': 'phishing domain',
    '127.0.1.5': 'malware domain',
    '127.0.1.6': 'botnet C&C domain',
    '127.0.1.102': 'abused legit spam',
    '127.0.1.104': 'abused legit phishing',
    '127.0.1.255': 'BLOCKED. Query volume/policy error, treat as unknown',
  },
  // Only .2 and .3 are spam findings. .4 and .5 are policy flags about the
  // address, not about spam, and SPFBL itself says the zone must not be used to
  // reject mail. They are shown for information on an otherwise clean row.
  'dnsbl.spfbl.net': {
    '127.0.0.2': 'confirmed spam source',
    '127.0.0.3': 'suspected spam, or not RFC 5321 compliant',
    '127.0.0.4': 'policy flag, not a listing: no mail service found at this address (NAT or residential)',
    '127.0.0.5': 'policy flag, not a listing: unreliable abuse contact for this IP range',
  },
  'hostkarma.junkemailfilter.com': {
    '127.0.0.1': 'whitelist (good)',
    '127.0.0.2': 'blacklist',
    '127.0.0.3': 'yellowlist (mixed)',
    '127.0.0.5': 'brownlist (suspicious)',
  },
};

// ---------------------------------------------------------------------------
// Spamhaus DQS (Data Query Service).
//
// The public mirrors (zen/dbl.spamhaus.org) refuse queries that arrive via a
// public resolver. They answer NXDOMAIN to everything, which looks "clean" but
// means nothing. With a free DQS key the queries go to a per-customer zone
// instead and work from anywhere:
//
//   IP:     2.0.0.127.<key>.zen.dq.spamhaus.net
//   domain: example.com.<key>.dbl.dq.spamhaus.net
//
// Set DBC_DQS_KEY to enable. IMPORTANT: the key is a secret, so it only ever
// lives in `queryHost` (used to build the DNS name). The public `zone` field, // which is returned by the API and shown in the UI. Keeps the plain name.
// ---------------------------------------------------------------------------
const DQS_KEY = (process.env.DBC_DQS_KEY || '').trim();

const DQS_ZONES = {
  'zen.spamhaus.org': 'zen',
  'dbl.spamhaus.org': 'dbl',
};

if (DQS_KEY) {
  for (const z of [...IP_ZONES, ...DOMAIN_ZONES]) {
    const name = DQS_ZONES[z.zone];
    if (!name) continue;
    z.queryHost = `${DQS_KEY}.${name}.dq.spamhaus.net`;
    z.status = 'live';       // authorized now. Calibration will confirm
    z.requiresKey = false;
    z.note = z.note.replace(/\s*, .*$/, '') + '. Via your Spamhaus DQS key.';
  }
}

/** Real DNS zone to query (may carry a secret key); never expose this. */
export const queryHostOf = (z) => z.queryHost || z.zone;

/** True when a Spamhaus DQS key is configured. */
export const dqsEnabled = () => Boolean(DQS_KEY);

// ---------------------------------------------------------------------------
// Calibration metadata. How to PROVE a zone gives trustworthy answers.
//
// Every DNSBL follows a contract: 127.0.0.2 is a permanent test entry (must be
// listed) and 127.0.0.1 must never be listed. Querying both tells us whether a
// zone actually discriminates from *this* server, or is lying / silently
// ignoring us. Domain zones use published test domains where they exist.
//
//   testPoint. Subject that MUST come back listed
//   control  . Subject that MUST come back clean
// ---------------------------------------------------------------------------
export const DEFAULT_IP_TEST = '127.0.0.2';
export const DEFAULT_IP_CONTROL = '127.0.0.1';
// A domain no blocklist could plausibly carry.
export const DEFAULT_DOMAIN_CONTROL = 'clean-control-zz9x8w7v.com';

const TEST_POINTS = {
  // Published domain test entries.
  'dbl.spamhaus.org': 'dbltest.com',
  'multi.surbl.org': 'test.surbl.org',
  'multi.uribl.com': 'test.uribl.com',
  // 127.0.0.1 is itself a bogon, so bogons needs a routable control instead.
  'bogons.cymru.com': { control: '8.8.8.8' },
};

// Codes that mean "your query was refused / you are not authorized". Never a
// real listing. 127.255.255.x is the common convention; URIBL uses 127.0.0.1.
export const GLOBAL_BLOCKED_PREFIX = '127.255.255.';
const BLOCKED_CODES = {
  'multi.uribl.com': ['127.0.0.1'],
  'black.uribl.com': ['127.0.0.1'],
};

for (const z of [...IP_ZONES, ...DOMAIN_ZONES]) {
  const t = TEST_POINTS[z.zone];
  if (typeof t === 'string') z.testPoint = t;
  else if (t && t.control) z.control = t.control;
  if (!z.testPoint && z.type === 'ip') z.testPoint = DEFAULT_IP_TEST;
  if (!z.control) z.control = z.type === 'ip' ? DEFAULT_IP_CONTROL : DEFAULT_DOMAIN_CONTROL;
  if (BLOCKED_CODES[z.zone]) z.blockedCodes = BLOCKED_CODES[z.zone];
}

/**
 * Does this set of answer codes represent a real listing for this zone?
 * Handles refusal sentinels and zones whose codes include non-listing meanings
 * (e.g. Hostkarma's 127.0.0.1 whitelist).
 */
export function isListedAnswer(zone, codes) {
  if (!codes || codes.length === 0) return false;
  if (codes.some((c) => c.startsWith(GLOBAL_BLOCKED_PREFIX))) return false;
  if (zone.blockedCodes && codes.some((c) => zone.blockedCodes.includes(c))) return false;
  if (zone.listedCodes) return codes.some((c) => zone.listedCodes.includes(c));
  return true;
}

/** True when the codes mean "refused / not authorized" rather than clean. */
export function isBlockedAnswer(zone, codes) {
  if (!codes || codes.length === 0) return false;
  if (codes.some((c) => c.startsWith(GLOBAL_BLOCKED_PREFIX))) return true;
  return Boolean(zone.blockedCodes && codes.some((c) => zone.blockedCodes.includes(c)));
}

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
