// The deliverability score. What actually decides whether mail lands.
//
// Three components, weighted by how much of real-world delivery each one
// gates. The weights live HERE and nowhere else: they are deliberately not
// sent to the UI or the API, so the exact split is not visible from outside.
// What callers get is each component's own 0-100 score and whether it could
// be measured, never the share it contributes.
//
//   blocklists  60  DNSBL / RHSBL listings. Spamhaus alone decides a large
//                   share of corporate and self-hosted delivery, which is why
//                   its zone weight dwarfs the minor lists inside this
//                   component.
//   reputation  25  The receiver-side systems that gate the big inboxes:
//                   Microsoft SNDS / O365 filtering, Google Postmaster,
//                   Cisco Talos, Proofpoint PDR. None of these answers a DNS
//                   query. Until an account is connected (SNDS access, a
//                   verified Postmaster domain) they cannot be measured, so
//                   they are EXCLUDED from the denominator rather than scored
//                   as perfect or as zero. The moment real data is wired in,
//                   it starts counting at this weight with no other change.
//   auth        15  SPF, DKIM, DMARC, MX, PTR. Necessary but not sufficient:
//                   perfect authentication with a bad reputation still lands
//                   in spam, which is why this is the smallest share.
//
// A component that could not be measured drops out of both sides of the
// division, the same rule used everywhere else in this codebase: absence of
// data is never scored as good news or bad news.

const COMPONENT_WEIGHTS = {
  blocklists: 60,
  reputation: 25,
  auth: 15,
};

/**
 * Blend the measurable components into one 0-100 score.
 *
 * @param {object} p  { blocklist, auth, reputation }  each 0-100 or null
 * @returns { score, standing, components }
 *          components = { blocklists|reputation|auth: { score, measured } }
 */
export function deliverabilityScore({ blocklist, auth, reputation } = {}) {
  const inputs = {
    blocklists: typeof blocklist === 'number' ? blocklist : null,
    reputation: typeof reputation === 'number' ? reputation : null,
    auth: typeof auth === 'number' ? auth : null,
  };

  let earned = 0;
  let possible = 0;
  const components = {};
  for (const [key, value] of Object.entries(inputs)) {
    const measured = value !== null;
    components[key] = { score: value, measured };
    if (measured) {
      earned += value * COMPONENT_WEIGHTS[key];
      possible += COMPONENT_WEIGHTS[key];
    }
  }

  const score = possible === 0 ? null : Math.round(earned / possible);

  let standing = 'good standing';
  if (score === null) standing = 'not measured';
  else if (score < 50) standing = 'poor';
  else if (score < 80) standing = 'at risk';

  return { score, standing, components };
}

// ---------------------------------------------------------------------------
// The reputation systems themselves.
//
// These are the receiver-side scores that no DNS query can read. Each entry
// says who it gates, what access it needs before it could ever feed the score,
// and a lookup URL a person can open right now. Scraping these is off the
// table: none has a public lookup API, and automated reads violate their terms
// and get this server's IP banned, exactly like automated delist submissions.
// ---------------------------------------------------------------------------

export const REPUTATION_SYSTEMS = [
  {
    key: 'gpt',
    name: 'Google Postmaster Tools',
    gates: 'Gmail and Google Workspace inboxes',
    means: 'Needs the domain verified with a DNS TXT record. Once verified, spam rate and compliance can be read through its API.',
    connectable: true,
    url: () => 'https://postmaster.google.com/managedomains',
  },
  {
    key: 'snds',
    name: 'Microsoft SNDS',
    gates: 'Outlook, Hotmail and Microsoft 365 inboxes',
    means: 'Needs proof that the sending IP range is yours. Reports complaint rate, trap hits and filter results for those IPs.',
    connectable: true,
    url: () => 'https://sendersupport.olc.protection.outlook.com/snds/',
  },
  {
    key: 'talos',
    name: 'Cisco Talos',
    gates: 'Cisco email gateways, common at large companies',
    means: 'Manual lookup only. No public API, and Neutral is already enough for some receivers to throttle.',
    connectable: false,
    url: (subject) => 'https://talosintelligence.com/reputation_center/lookup?search=' + encodeURIComponent(subject || ''),
  },
  {
    key: 'pdr',
    name: 'Proofpoint Dynamic Reputation',
    gates: 'Proofpoint gateways, common at large companies',
    means: 'Manual lookup only. No public API; delisting goes through the same page.',
    connectable: false,
    url: () => 'https://ipcheck.proofpoint.com/',
  },
];

/**
 * The reputation systems as report rows for one subject: lookup URL filled in,
 * status 'manual' until a real integration supplies data. No weights included.
 */
export function reputationReport({ ip, domain } = {}) {
  return REPUTATION_SYSTEMS.map((s) => ({
    key: s.key,
    name: s.name,
    gates: s.gates,
    means: s.means,
    connectable: s.connectable,
    url: s.url(s.key === 'talos' ? (ip || domain) : ip),
    status: 'manual', // becomes 'connected' when live data feeds the score
  }));
}
