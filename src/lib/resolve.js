import { Resolver } from 'node:dns/promises';

// A dedicated resolver so we can control timeout/tries and, in production, point
// at our own recursive resolver (Unbound) — public resolvers like 8.8.8.8 get
// blocked by Spamhaus and poison every result (plan §5.1).
//
//   DBC_RESOLVERS=127.0.0.1,192.168.1.53  (comma-separated IP addresses only)
//
// If unset we inherit the system resolvers, which is fine for local dev but NOT
// for a deployed service that queries Spamhaus.
export function buildResolver(servers, opts = {}) {
  const resolver = new Resolver({ timeout: opts.timeout ?? 3000, tries: opts.tries ?? 1 });
  const list =
    servers ||
    (process.env.DBC_RESOLVERS
      ? process.env.DBC_RESOLVERS.split(',').map((s) => s.trim()).filter(Boolean)
      : null);
  if (list && list.length) {
    // setServers() only accepts IP addresses (optionally with port), never
    // hostnames. Silently skip any entry that looks like a hostname so a
    // mis-configured DBC_RESOLVERS (e.g. a DQS hostname) doesn't crash the
    // server on startup.
    const ipOnly = list.filter((s) => /^[\d.:]+$/.test(s.replace(/^\[/, '').split(']')[0]));
    if (ipOnly.length) resolver.setServers(ipOnly);
  } else {
    // No explicit servers: normally c-ares inherits the system DNS. On some
    // setups (notably Windows) it comes up with NO servers, so every query
    // fails instantly and the whole app looks broken. Fall back to public
    // resolvers in that case so the tool at least works. (Set DBC_RESOLVERS to
    // your own recursive resolver in production — see plan §5.1.)
    try {
      if (!resolver.getServers || resolver.getServers().length === 0) {
        resolver.setServers(['1.1.1.1', '8.8.8.8']);
      }
    } catch {
      resolver.setServers(['1.1.1.1', '8.8.8.8']);
    }
  }
  return resolver;
}

// ---------------------------------------------------------------------------
// Spamhaus DQS (Data Query Service) support
// ---------------------------------------------------------------------------
// Set DBC_DQS_KEY to your personal DQS key from https://portal.spamhaus.com
// The key is used as a subdomain prefix for Spamhaus zones so queries go
// through the authorised DQS resolver instead of the public mirrors:
//
//   zen.spamhaus.org   →  <key>.zen.dq.spamhaus.net
//   dbl.spamhaus.org   →  <key>.dbl.dq.spamhaus.net
//   (any *.spamhaus.org zone follows the same pattern)
//
// Public resolvers like 8.8.8.8 are blocked by Spamhaus — DQS removes that
// restriction and gives accurate results from any cloud/shared host.
const DQS_KEY = (process.env.DBC_DQS_KEY || '').trim();

/**
 * Rewrite a DNSBL zone name to its DQS equivalent when a key is configured.
 * Non-Spamhaus zones are returned unchanged.
 */
export function dqsZone(zone) {
  if (!DQS_KEY) return zone;
  // Match *.spamhaus.org  (e.g. zen, dbl, sbl, xbl, pbl, zrd, authbl, …)
  const m = zone.match(/^([^.]+)\.spamhaus\.org$/);
  if (m) return `${DQS_KEY}.${m[1]}.dq.spamhaus.net`;
  return zone;
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
 * Query a single (subject, zone) pair, capturing TTL and response time.
 *
 * A listed entry answers with a 127.0.0.x A record; a clean entry answers
 * NXDOMAIN/ENOTFOUND. Crucially, a timeout is NOT "clean" — it's `listed: null`
 * (unknown), so we never give a false all-clear (plan §5.4).
 *
 * Combined lists (e.g. Hostkarma) encode a *whitelist* in 127.0.0.1: when a
 * zone declares `listedCodes`, a hit only counts as listed if a returned code
 * is in that set — otherwise it's a clean/whitelist answer, not a listing.
 *
 * @param subject reversed IP (for ip zones) or the domain (for domain zones)
 * @returns { zone, listed: true|false|null, codes?, ttl?, responseMs, error? }
 */
export async function queryZone(subject, zoneMeta, resolver, opts = {}) {
  // Use the DQS-rewritten zone name when a key is configured so Spamhaus
  // queries hit the authorised DQS resolver instead of the blocked public mirror.
  const fqdn = `${subject}.${dqsZone(zoneMeta.zone)}`;
  const started = Date.now();
  // Whether we trust "listed" answers from key-required zones. Without a key /
  // authorized resolver these lists return a positive for *every* query, so we
  // downgrade them to "unknown" unless the operator opts in (DBC_TRUST_KEYED).
  const trustKeyed = opts.trustKeyed ?? process.env.DBC_TRUST_KEYED === 'true';
  try {
    const records = await resolver.resolve4(fqdn, { ttl: true });
    const responseMs = Date.now() - started;
    const codes = records.map((r) => r.address);
    const ttl = records.reduce((m, r) => Math.min(m, r.ttl), Infinity);
    const ttlOut = Number.isFinite(ttl) ? ttl : null;

    // 127.255.255.x is the conventional "query blocked / not authorized"
    // sentinel range (Spamhaus .254, Sender Score .255, etc.) — never a real
    // listing; report as unknown (plan §5.1).
    if (codes.some((c) => c.startsWith('127.255.255.'))) {
      return { ...zoneMeta, listed: null, error: 'PUBLIC_RESOLVER_BLOCKED', codes, responseMs };
    }
    // Respect a zone's listedCodes filter (whitelist vs blacklist answers).
    if (zoneMeta.listedCodes && !codes.some((c) => zoneMeta.listedCodes.includes(c))) {
      return { ...zoneMeta, listed: false, codes, ttl: ttlOut, responseMs };
    }
    // Key-required list returned a hit but we're not authorized -> untrusted.
    if (zoneMeta.requiresKey && !trustKeyed) {
      return { ...zoneMeta, listed: null, error: 'REQUIRES_KEY', codes, responseMs };
    }
    return { ...zoneMeta, listed: true, codes, ttl: ttlOut, responseMs };
  } catch (e) {
    const responseMs = Date.now() - started;
    if (NOT_FOUND.has(e.code)) return { ...zoneMeta, listed: false, responseMs };
    // ETIMEOUT, ESERVFAIL, REFUSED, etc. -> unknown.
    return { ...zoneMeta, listed: null, error: e.code || 'ERROR', responseMs };
  }
}
