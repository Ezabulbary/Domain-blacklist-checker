import { buildResolver } from './resolve.js';

// Selectors we probe when the caller doesn't know the DKIM selector. Covers the
// big senders (Google, Microsoft/O365, Amazon SES, Mailchimp, SendGrid, etc.).
const COMMON_SELECTORS = [
  'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2',
  'default', 'dkim', 'mail', 'smtp', 'mandrill', 'mxvault',
  'sendgrid', 'sig1', 'scph0819', 'protonmail', 'zoho', 'fm1',
];

const flat = (txt) => (Array.isArray(txt) ? txt.join('') : String(txt));

/**
 * Full authentication health for a domain: SPF, DKIM, DMARC, MX and PTR, all
 * from live DNS. Returns a structured object plus a 0-100 auth score.
 *
 * @param {string} domain      registrable / mail domain
 * @param {object} [opts]      { resolver, ips, selectors }
 */
export async function checkAuth(domain, opts = {}) {
  // Auth TXT records (especially SPF on big senders) can be large and slow, so
  // this resolver gets a longer timeout and a retry than the DNSBL one.
  const resolver = opts.resolver || buildResolver(null, { timeout: 5000, tries: 2 });
  const selectors = opts.selectors || COMMON_SELECTORS;

  const [spf, dmarc, mx, dkim, ptr] = await Promise.all([
    checkSpf(domain, resolver),
    checkDmarc(domain, resolver),
    checkMx(domain, resolver),
    checkDkim(domain, selectors, resolver),
    opts.ips && opts.ips.length ? checkPtr(opts.ips, domain, resolver) : Promise.resolve(null),
  ]);

  const score = authScore({ spf, dkim, dmarc, ptr });
  return { spf, dkim, dmarc, mx, ptr, score };
}

/** SPF: find the v=spf1 record, read the all-qualifier, count DNS lookups. */
export async function checkSpf(domain, resolver) {
  try {
    const txt = (await resolver.resolveTxt(domain)).map(flat);
    const record = txt.find((t) => /^v=spf1\b/i.test(t.trim()));
    if (!record) return { present: false, status: 'missing', record: null };

    const all = record.match(/([-~?+])all\b/i);
    const qualifier = all ? all[1] : null;
    const policy = { '-': 'fail (-all)', '~': 'softfail (~all)', '?': 'neutral (?all)', '+': 'pass (+all, unsafe)' }[qualifier] || 'no all mechanism';
    // Count mechanisms that cost a DNS lookup (RFC 7208 limit of 10). Tokenize
    // so the "a" in "all" and bare a/mx mechanisms are handled correctly.
    const LOOKUP_MECH = new Set(['include', 'a', 'mx', 'ptr', 'exists', 'redirect']);
    const lookups = record
      .trim()
      .split(/\s+/)
      .slice(1) // drop "v=spf1"
      .map((t) => t.replace(/^[+\-~?]/, '').split(/[:/=]/)[0].toLowerCase())
      .filter((m) => LOOKUP_MECH.has(m)).length;

    let status = 'pass';
    if (!qualifier || qualifier === '+') status = 'warn';
    if (lookups > 10) status = 'warn';
    return { present: true, status, record, qualifier, policy, lookups, tooManyLookups: lookups > 10 };
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return { present: false, status: 'missing', record: null };
    return { present: false, status: 'unknown', record: null, error: e.code };
  }
}

/** DMARC: parse the _dmarc TXT policy. */
export async function checkDmarc(domain, resolver) {
  try {
    const txt = (await resolver.resolveTxt(`_dmarc.${domain}`)).map(flat);
    const record = txt.find((t) => /^v=DMARC1\b/i.test(t.trim()));
    if (!record) return { present: false, status: 'missing', record: null };

    const tags = {};
    for (const part of record.split(';')) {
      const [k, v] = part.split('=').map((s) => s && s.trim());
      if (k && v) tags[k.toLowerCase()] = v;
    }
    const p = (tags.p || 'none').toLowerCase();
    const status = p === 'reject' ? 'pass' : p === 'quarantine' ? 'warn' : 'warn';
    return {
      present: true,
      status,
      record,
      policy: p,
      subdomainPolicy: tags.sp || null,
      pct: tags.pct ? Number(tags.pct) : 100,
      rua: tags.rua || null,
      ruf: tags.ruf || null,
      alignment: { spf: tags.aspf || 'r', dkim: tags.adkim || 'r' },
    };
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return { present: false, status: 'missing', record: null };
    return { present: false, status: 'unknown', record: null, error: e.code };
  }
}

/** DKIM: probe selectors and report any that publish a key. */
export async function checkDkim(domain, selectors, resolver) {
  const found = [];
  await Promise.all(
    selectors.map(async (sel) => {
      try {
        const txt = (await resolver.resolveTxt(`${sel}._domainkey.${domain}`)).map(flat).join('');
        if (/v=DKIM1|k=rsa|p=[A-Za-z0-9]/i.test(txt)) {
          found.push({ selector: sel, keyType: (txt.match(/k=([a-z0-9]+)/i) || [])[1] || 'rsa' });
        }
      } catch {
        /* selector not published. Normal */
      }
    }),
  );
  return {
    present: found.length > 0,
    status: found.length > 0 ? 'pass' : 'unknown',
    selectors: found,
    note: found.length ? undefined : 'no key found for common selectors. Provide the real selector to confirm',
  };
}

/**
 * MX records, sorted by priority.
 *
 * `records` is always an array, including on a transient failure. Callers read
 * `records.length` directly, and a batch of a few hundred domains will always
 * hit at least one ETIMEOUT/ESERVFAIL, so an absent field there would crash the
 * whole run.
 */
export async function checkMx(domain, resolver) {
  try {
    const mx = (await resolver.resolveMx(domain)).sort((a, b) => a.priority - b.priority);
    return { present: mx.length > 0, status: mx.length ? 'pass' : 'missing', records: mx.map((r) => ({ exchange: r.exchange, priority: r.priority })) };
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return { present: false, status: 'missing', records: [] };
    return { present: false, status: 'unknown', records: [], error: e.code };
  }
}

/** PTR / rDNS for each IP, forward-confirmed (FCrDNS) where possible. */
export async function checkPtr(ips, domain, resolver) {
  const results = await Promise.all(
    ips.map(async (ip) => {
      try {
        const names = await resolver.reverse(ip);
        const host = names[0] || null;
        let forwardConfirmed = false;
        if (host) {
          try {
            const back = await resolver.resolve4(host);
            forwardConfirmed = back.includes(ip);
          } catch { /* forward lookup failed */ }
        }
        return { ip, host, forwardConfirmed };
      } catch (e) {
        return { ip, host: null, forwardConfirmed: false, error: e.code };
      }
    }),
  );
  const valid = results.every((r) => r.host);
  return { present: results.some((r) => r.host), status: valid ? 'pass' : 'warn', records: results };
}

/** Weighted 0-100 authentication score. */
export function authScore({ spf, dkim, dmarc, ptr }) {
  let s = 0;
  // SPF up to 30
  if (spf?.present) s += spf.status === 'pass' ? 30 : 18;
  // DKIM up to 25
  if (dkim?.present) s += 25;
  // DMARC up to 35 (reject > quarantine > none)
  if (dmarc?.present) s += dmarc.policy === 'reject' ? 35 : dmarc.policy === 'quarantine' ? 24 : 12;
  // PTR up to 10 (only when we had IPs to check)
  if (ptr) s += ptr.status === 'pass' ? 10 : 4;
  else s += 10; // no IPs to penalize (domain-only check)
  return Math.min(100, Math.round(s));
}
