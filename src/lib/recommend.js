// Turn a report's findings into concrete, prioritized recommendations. The
// "what do I actually do about this" layer (like the reference tool's
// Recommendations tab). Pure function over { auth, table }: no I/O.
//
// Each recommendation: { severity, area, title, detail, action? }
//   severity: 'critical' | 'high' | 'medium' | 'low'

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

export function recommend({ auth, table = [] } = {}) {
  const recs = [];
  const add = (r) => recs.push(r);

  // --- Blacklist listings ---
  const listings = table.filter((r) => r.state === 'listed');
  for (const l of listings) {
    add({
      severity: l.severity === 'critical' ? 'critical' : l.severity === 'high' ? 'high' : 'medium',
      area: 'blacklist',
      title: `Listed on ${l.name}`,
      detail: `${l.subject} is listed on ${l.zone}. This can hurt delivery${l.severity === 'critical' ? ' significantly (major list)' : ''}.`,
      action: l.delist ? { label: 'Request delisting', url: l.delist } : undefined,
    });
  }

  // --- SPF ---
  if (auth?.spf) {
    if (!auth.spf.present) {
      add({ severity: 'high', area: 'spf', title: 'No SPF record', detail: 'Publish an SPF TXT record so receivers can validate which hosts may send for your domain.', action: { label: 'SPF syntax', url: 'https://www.rfc-editor.org/rfc/rfc7208' } });
    } else {
      if (auth.spf.qualifier === '+' || !auth.spf.qualifier) {
        add({ severity: 'medium', area: 'spf', title: 'Weak SPF all-mechanism', detail: `SPF ends in "${auth.spf.qualifier || 'no'}all". Use "-all" (hard fail) or at least "~all" (soft fail) to be effective.` });
      }
      if (auth.spf.tooManyLookups) {
        add({ severity: 'medium', area: 'spf', title: 'SPF exceeds 10 DNS lookups', detail: `SPF requires ${auth.spf.lookups} DNS lookups; over 10 causes a permerror. Flatten or consolidate includes.` });
      }
    }
  }

  // --- DKIM ---
  if (auth?.dkim && !auth.dkim.present) {
    add({ severity: 'high', area: 'dkim', title: 'No DKIM key found', detail: 'No DKIM key was found for common selectors. Publish DKIM and sign outbound mail (provide your real selector to confirm).' });
  }

  // --- DMARC ---
  if (auth?.dmarc) {
    if (!auth.dmarc.present) {
      add({ severity: 'high', area: 'dmarc', title: 'No DMARC record', detail: 'Publish a _dmarc TXT record (start with p=none + rua to monitor, then tighten).', action: { label: 'DMARC guide', url: 'https://dmarc.org/overview/' } });
    } else if (auth.dmarc.policy === 'none') {
      add({ severity: 'medium', area: 'dmarc', title: 'DMARC policy is p=none', detail: 'p=none only monitors. Once your reports look clean, move to p=quarantine then p=reject to actually block spoofing.' });
    } else if (auth.dmarc.policy === 'quarantine') {
      add({ severity: 'low', area: 'dmarc', title: 'Consider DMARC p=reject', detail: 'You are at p=quarantine. p=reject gives the strongest protection once you are confident in alignment.' });
    }
    if (auth.dmarc.present && !auth.dmarc.rua) {
      add({ severity: 'low', area: 'dmarc', title: 'No DMARC aggregate reporting', detail: 'Add a rua= address to receive aggregate reports and gain visibility into your mail streams.' });
    }
  }

  // --- PTR / rDNS ---
  if (auth?.ptr && auth.ptr.status !== 'pass') {
    const bad = (auth.ptr.records || []).filter((r) => !r.host).map((r) => r.ip);
    add({ severity: 'medium', area: 'ptr', title: 'Missing or invalid PTR', detail: `Sending IP(s) ${bad.join(', ') || ''} lack valid reverse DNS. Set PTR records (and forward-confirm them) to avoid rejection.` });
  }

  recs.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  return recs;
}
