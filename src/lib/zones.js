// DNSBL zone catalog.
//
// Each zone has a `weight` so that a Spamhaus hit counts far more than an
// informational SORBS hit (see plan §2 / §5.6). Weights feed the 0-100 score.
//
//   type: 'ip'     -> query reversed-octet IP against the zone
//   type: 'domain' -> query the registrable domain directly against the zone
//
// `severity` drives the UI badge; `delist` is the human-facing removal link so
// a listing is actionable, not just a red flag (plan §5.6).

export const IP_ZONES = [
  {
    zone: 'zen.spamhaus.org',
    weight: 40,
    severity: 'critical',
    note: 'Spamhaus ZEN (SBL+XBL+PBL) — most important IP blocklist.',
    delist: 'https://check.spamhaus.org/',
  },
  {
    zone: 'b.barracudacentral.org',
    weight: 20,
    severity: 'high',
    note: 'Barracuda Reputation Block List (registration required for queries).',
    delist: 'https://www.barracudacentral.org/rbl/removal-request',
  },
  {
    zone: 'bl.spamcop.net',
    weight: 15,
    severity: 'high',
    note: 'SpamCop Blocking List — auto-expires; fix source then wait.',
    delist: 'https://www.spamcop.net/bl.shtml',
  },
  {
    zone: 'psbl.surriel.com',
    weight: 10,
    severity: 'medium',
    note: 'Passive Spam Block List.',
    delist: 'https://psbl.org/remove',
  },
  {
    zone: 'dnsbl.sorbs.net',
    weight: 5,
    severity: 'low',
    note: 'SORBS aggregate — informational, high false-positive rate.',
    delist: 'https://www.sorbs.net/',
  },
  {
    zone: 'dnsbl-1.uceprotect.net',
    weight: 8,
    severity: 'medium',
    note: 'UCEPROTECT Level 1 (single IP).',
    delist: 'https://www.uceprotect.net/en/rblcheck.php',
  },
  {
    zone: 'spam.dnsbl.sorbs.net',
    weight: 5,
    severity: 'low',
    note: 'SORBS spam sub-zone.',
    delist: 'https://www.sorbs.net/',
  },
  {
    zone: 'cbl.abuseat.org',
    weight: 18,
    severity: 'high',
    note: 'Composite Blocking List (feeds Spamhaus XBL) — indicates malware/bot.',
    delist: 'https://www.abuseat.org/lookup.cgi',
  },
];

export const DOMAIN_ZONES = [
  {
    zone: 'dbl.spamhaus.org',
    weight: 40,
    severity: 'critical',
    note: 'Spamhaus Domain Block List — most important domain blocklist.',
    delist: 'https://check.spamhaus.org/',
  },
  {
    zone: 'multi.surbl.org',
    weight: 20,
    severity: 'high',
    note: 'SURBL multi — spam/phishing/malware URIs.',
    delist: 'https://www.surbl.org/delisting',
  },
  {
    zone: 'multi.uribl.com',
    weight: 18,
    severity: 'high',
    note: 'URIBL multi — domains seen in unsolicited email.',
    delist: 'https://admin.uribl.com/',
  },
  {
    zone: 'dbl.nordspam.com',
    weight: 10,
    severity: 'medium',
    note: 'NordSpam domain blocklist.',
    delist: 'https://www.nordspam.com/removal/',
  },
];

// Some zones encode meaning in the returned 127.0.0.x address. When we know the
// map we surface a human string; otherwise we just show the raw code.
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
    '127.0.1.103': 'abused spammed redirector',
    '127.0.1.104': 'abused legit phishing',
    '127.0.1.105': 'abused legit malware',
    '127.0.1.106': 'abused legit botnet C&C',
    '127.0.1.255': 'BLOCKED — query volume/policy error, treat as unknown',
  },
};

export const ALL_ZONES = [...IP_ZONES, ...DOMAIN_ZONES];
