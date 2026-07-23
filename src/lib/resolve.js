import { Resolver } from 'node:dns/promises';

// A dedicated resolver so we can control timeout/tries and, in production, point
// at our own recursive resolver (Unbound) — public resolvers like 8.8.8.8 get
// blocked by Spamhaus and poison every result (plan §5.1).
//
//   DBC_RESOLVERS=127.0.0.1,192.168.1.53  (comma-separated)
//
// If unset we inherit the system resolvers, which is fine for local dev but NOT
// for a deployed service that queries Spamhaus.
export function buildResolver(servers) {
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  const list =
    servers ||
    (process.env.DBC_RESOLVERS
      ? process.env.DBC_RESOLVERS.split(',').map((s) => s.trim()).filter(Boolean)
      : null);
  if (list && list.length) resolver.setServers(list);
  return resolver;
}

/** DNS errors that genuinely mean "no such record" vs. a transient failure. */
const NOT_FOUND = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN']);

/**
 * Resolve the mail-relevant records for a domain. Missing records are normal
 * (a parked domain may have no MX); only unexpected errors are surfaced.
 *
 * Returns { a: string[], aaaa: string[], mx: string[], errors: {...} }.
 */
export async function resolveDomain(domain, resolver) {
  const out = { a: [], aaaa: [], mx: [], errors: {} };

  const [a, aaaa, mx] = await Promise.allSettled([
    resolver.resolve4(domain),
    resolver.resolve6(domain),
    resolver.resolveMx(domain),
  ]);

  if (a.status === 'fulfilled') out.a = a.value;
  else if (!NOT_FOUND.has(a.reason?.code)) out.errors.a = a.reason?.code || 'error';

  if (aaaa.status === 'fulfilled') out.aaaa = aaaa.value;
  else if (!NOT_FOUND.has(aaaa.reason?.code)) out.errors.aaaa = aaaa.reason?.code || 'error';

  if (mx.status === 'fulfilled') {
    out.mx = mx.value.sort((x, y) => x.priority - y.priority).map((r) => r.exchange);
  } else if (!NOT_FOUND.has(mx.reason?.code)) {
    out.errors.mx = mx.reason?.code || 'error';
  }

  return out;
}

/** 1.2.3.4 -> 4.3.2.1 (reversed octets for DNSBL queries). */
export const reverseIp = (ip) => ip.split('.').reverse().join('.');

/**
 * Query a single (subject, zone) pair.
 *
 * A listed entry answers with a 127.0.0.x A record; a clean entry answers
 * NXDOMAIN/ENOTFOUND. Crucially, a timeout is NOT "clean" — it's `listed: null`
 * (unknown), so we never give a false all-clear (plan §5.4).
 *
 * @param subject reversed IP (for ip zones) or the domain (for domain zones)
 * @returns { zone, listed: true|false|null, codes?, error? }
 */
export async function queryZone(subject, zoneMeta, resolver) {
  const fqdn = `${subject}.${zoneMeta.zone}`;
  try {
    const codes = await resolver.resolve4(fqdn);
    // 127.255.255.254 is the standard "you are querying from a blocked/public
    // resolver" sentinel — treat as unknown, not listed (plan §5.1).
    if (codes.includes('127.255.255.254')) {
      return { ...zoneMeta, listed: null, error: 'PUBLIC_RESOLVER_BLOCKED', codes };
    }
    return { ...zoneMeta, listed: true, codes };
  } catch (e) {
    if (NOT_FOUND.has(e.code)) return { ...zoneMeta, listed: false };
    // ETIMEOUT, ESERVFAIL, REFUSED, etc. -> unknown.
    return { ...zoneMeta, listed: null, error: e.code || 'ERROR' };
  }
}
