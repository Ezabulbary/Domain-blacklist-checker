// Which email service a domain actually uses, read from its MX records.
//
// The MX host is the one piece of public DNS that says where a domain's mail
// really goes, so detection works from a suffix match on the MX hostnames.
// Order matters: security gateways (Mimecast, Proofpoint, Barracuda) sit IN
// FRONT of Google or Microsoft, so when a gateway matches, the gateway is the
// answer; naming the provider hidden behind it would be a guess.

const RULES = [
  // Security gateways first. Their MX replaces the real provider's.
  { key: 'mimecast', name: 'Mimecast (gateway)', suffixes: ['mimecast.com', 'mimecast-offshore.com'] },
  { key: 'proofpoint', name: 'Proofpoint (gateway)', suffixes: ['pphosted.com', 'ppe-hosted.com', 'gpphosted.com'] },
  { key: 'barracuda', name: 'Barracuda (gateway)', suffixes: ['barracudanetworks.com', 'ess.barracudanetworks.com'] },
  { key: 'messagelabs', name: 'Broadcom/Symantec (gateway)', suffixes: ['messagelabs.com'] },
  { key: 'sophos', name: 'Sophos (gateway)', suffixes: ['sophos.com', 'reflexion.net'] },
  { key: 'trendmicro', name: 'Trend Micro (gateway)', suffixes: ['tmes.trendmicro.com', 'tmes.trendmicro.eu'] },

  // The big mailbox providers.
  { key: 'google', name: 'Google Workspace', suffixes: ['google.com', 'googlemail.com'] },
  { key: 'microsoft', name: 'Microsoft 365', suffixes: ['protection.outlook.com', 'hotmail.com'] },
  { key: 'zoho', name: 'Zoho Mail', suffixes: ['zoho.com', 'zoho.eu', 'zoho.in', 'zohomail.com'] },
  { key: 'proton', name: 'Proton Mail', suffixes: ['protonmail.ch', 'proton.me'] },
  { key: 'yahoo', name: 'Yahoo', suffixes: ['yahoodns.net'] },
  { key: 'fastmail', name: 'Fastmail', suffixes: ['messagingengine.com', 'fastmail.com'] },
  { key: 'icloud', name: 'Apple iCloud Mail', suffixes: ['icloud.com'] },
  { key: 'yandex', name: 'Yandex Mail', suffixes: ['yandex.net', 'yandex.ru'] },
  { key: 'mailru', name: 'Mail.ru', suffixes: ['mail.ru'] },

  // Hosting / registrar mail.
  { key: 'godaddy', name: 'GoDaddy Email', suffixes: ['secureserver.net'] },
  { key: 'namecheap', name: 'Namecheap Private Email', suffixes: ['privateemail.com', 'registrar-servers.com', 'web-hosting.com'] },
  { key: 'titan', name: 'Titan (Hostinger)', suffixes: ['titan.email'] },
  { key: 'ionos', name: 'IONOS', suffixes: ['kundenserver.de', 'ui-dns.com', 'ionos.com', 'perfora.net'] },
  { key: 'ovh', name: 'OVH', suffixes: ['ovh.net', 'ovh.ca'] },
  { key: 'rackspace', name: 'Rackspace Email', suffixes: ['emailsrvr.com'] },
  { key: 'one', name: 'one.com', suffixes: ['one.com'] },
  { key: 'gandi', name: 'Gandi Mail', suffixes: ['gandi.net'] },
  { key: 'infomaniak', name: 'Infomaniak', suffixes: ['infomaniak.ch'] },
  { key: 'migadu', name: 'Migadu', suffixes: ['migadu.com'] },
  { key: 'mxroute', name: 'MXroute', suffixes: ['mxroute.com', 'mxrouting.net'] },

  // Sending platforms occasionally used as MX for inbound routing.
  { key: 'amazon', name: 'Amazon WorkMail / SES', suffixes: ['awsapps.com', 'amazonaws.com'] },
  { key: 'mailgun', name: 'Mailgun', suffixes: ['mailgun.org'] },
  { key: 'zonemta', name: 'Forward Email', suffixes: ['forwardemail.net'] },
  { key: 'improvmx', name: 'ImprovMX (forwarding)', suffixes: ['improvmx.com'] },
  { key: 'cloudflare', name: 'Cloudflare Email Routing', suffixes: ['mx.cloudflare.net'] },
];

// The registrable tail of an MX host, for the "other" label: mail.foo.co.uk
// stays recognisable without dragging the whole hostname into a table cell.
function tail(host) {
  const parts = String(host).replace(/\.$/, '').split('.');
  return parts.slice(-Math.min(parts.length, 2)).join('.');
}

/**
 * @param {string[]} mxHosts  MX exchange hostnames (any order)
 * @returns {{ key, name }}
 *   key 'none' when the domain has no MX at all (it cannot receive mail),
 *   'other' with the MX tail in the name when nothing known matches.
 */
export function detectProvider(mxHosts) {
  const hosts = (mxHosts || []).map((h) => String(h || '').toLowerCase().replace(/\.$/, '')).filter(Boolean);
  if (!hosts.length) return { key: 'none', name: 'No mail service (no MX)' };
  for (const rule of RULES) {
    for (const host of hosts) {
      if (rule.suffixes.some((sfx) => host === sfx || host.endsWith('.' + sfx))) {
        return { key: rule.key, name: rule.name };
      }
    }
  }
  return { key: 'other', name: 'Other (' + tail(hosts[0]) + ')' };
}
