import { domainToASCII } from 'node:url';
import { parse } from 'tldts';

/**
 * Normalize arbitrary user input into a registrable domain we can query.
 *
 *   "https://www.Bücher.de/path?q=1" -> "xn--bcher-kva.de"
 *   "  Mail.EXAMPLE.co.uk "          -> "example.co.uk"
 *
 * Steps (plan §3):
 *   1. trim + lowercase
 *   2. strip scheme, path, query, port, credentials, leading "www."
 *   3. punycode (IDN -> ASCII)
 *   4. public-suffix -> registrable ("apex") domain
 *
 * Returns { input, host, domain, isIp, isValid, error }.
 */
export function normalizeDomain(raw) {
  const result = {
    input: raw,
    host: null,
    domain: null,
    isIp: false,
    isValid: false,
    error: null,
  };

  if (typeof raw !== 'string' || raw.trim() === '') {
    result.error = 'empty input';
    return result;
  }

  let host = raw.trim().toLowerCase();

  // Strip scheme if present.
  host = host.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  // Strip credentials (user:pass@).
  host = host.replace(/^[^@/]*@/, '');
  // Cut at first path / query / fragment separator.
  host = host.split(/[/?#]/)[0];
  // Strip port.
  host = host.replace(/:\d+$/, '');
  // Strip a single trailing dot (root label).
  host = host.replace(/\.$/, '');
  // Strip leading www.
  host = host.replace(/^www\./, '');

  if (host === '') {
    result.error = 'could not extract a host';
    return result;
  }

  // IPv4 literal? Then there's no registrable domain — the IP is the subject.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const octets = host.split('.').map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) {
      result.host = host;
      result.domain = host;
      result.isIp = true;
      result.isValid = true;
      return result;
    }
    result.error = 'invalid IPv4 literal';
    return result;
  }

  // IDN -> ASCII (punycode). domainToASCII returns '' on failure.
  const ascii = domainToASCII(host) || host;

  const parsed = parse(ascii, { allowPrivateDomains: false });
  if (!parsed.domain || !parsed.isIcann) {
    result.host = ascii;
    result.error = 'not a registrable domain (unknown/invalid TLD)';
    return result;
  }

  result.host = ascii;
  result.domain = parsed.domain;
  result.isValid = true;
  return result;
}
