// API key scopes.
//
// A key is created for a job, so it should only be able to do that job. A key
// that lives in a client's reporting script has no business rotating keys or
// pulling another tenant's history, and if it leaks, the damage is bounded by
// what it was allowed to do rather than by what the API can do.
//
// Scopes are `resource:action`. The catalog is the single source of truth: the
// route table below, the create form, and the docs all read from it, so adding
// an endpoint without deciding its scope is not possible by accident.

export const SCOPES = [
  {
    key: 'check:read',
    label: 'Blacklist check',
    detail: 'Check one domain or IP against the blocklists.',
    endpoints: ['GET /api/check'],
  },
  {
    key: 'bulk:write',
    label: 'Bulk check',
    detail: 'Check many domains in one request. Separate from check:read because one call fans out to thousands of DNS queries.',
    endpoints: ['POST /api/check/bulk'],
  },
  {
    key: 'analyze:read',
    label: 'Full report',
    detail: 'Blocklists, authentication, risk score and recommendations together.',
    endpoints: ['GET /api/analyze'],
  },
  {
    key: 'auth:read',
    label: 'Email authentication',
    detail: 'SPF, DKIM, DMARC, MX and PTR for a domain.',
    endpoints: ['GET /api/auth'],
  },
  {
    key: 'zones:read',
    label: 'Catalog and calibration',
    detail: 'The blocklist catalog and which lists this server can trust.',
    endpoints: ['GET /api/zones', 'GET /api/calibration'],
  },
  {
    key: 'removal:read',
    label: 'Delisting help',
    detail: 'Removal guidance, readiness checks and prefilled removal links.',
    endpoints: ['GET /api/removal', 'GET /api/delist/start', 'GET /api/delist/status'],
  },
  {
    key: 'history:read',
    label: 'Check history',
    detail: 'Past checks for a domain. Requires a database.',
    endpoints: ['GET /api/history'],
  },
  {
    key: 'keys:write',
    label: 'Manage API keys',
    detail: 'Create and revoke API keys. Grant this only to a key you use for provisioning.',
    endpoints: ['POST /api/keys', 'GET /api/keys', 'DELETE /api/keys/:id'],
  },
];

/** Grants everything, including scopes added in future versions. */
export const ALL_SCOPE = 'all:all';

export const SCOPE_KEYS = SCOPES.map((s) => s.key);
const VALID = new Set([ALL_SCOPE, ...SCOPE_KEYS]);

/** Which scope an endpoint needs. Anything absent here needs no key scope. */
export const ROUTE_SCOPES = {
  'GET /api/check': 'check:read',
  'POST /api/check/bulk': 'bulk:write',
  'GET /api/analyze': 'analyze:read',
  'GET /api/auth': 'auth:read',
  'GET /api/zones': 'zones:read',
  'GET /api/calibration': 'zones:read',
  'GET /api/removal': 'removal:read',
  'GET /api/delist/start': 'removal:read',
  'GET /api/delist/status': 'removal:read',
  'GET /api/history': 'history:read',
  'POST /api/keys': 'keys:write',
  'GET /api/keys': 'keys:write',
};

/**
 * Clean a requested scope list.
 * Returns { scopes, invalid }. `all:all` collapses to itself, since keeping the
 * individual scopes alongside it would imply the key is limited to them.
 */
export function normalizeScopes(input) {
  const list = Array.isArray(input) ? input : typeof input === 'string' ? input.split(/[\s,]+/) : [];
  const cleaned = list.map((s) => String(s || '').trim().toLowerCase()).filter(Boolean);
  const invalid = [...new Set(cleaned.filter((s) => !VALID.has(s)))];
  const valid = [...new Set(cleaned.filter((s) => VALID.has(s)))];
  if (valid.includes(ALL_SCOPE)) return { scopes: [ALL_SCOPE], invalid };
  return { scopes: valid, invalid };
}

/** Does this key's scope list permit `needed`? */
export function hasScope(granted, needed) {
  if (!needed) return true;
  if (!Array.isArray(granted)) return false;
  return granted.includes(ALL_SCOPE) || granted.includes(needed);
}

/** The scope a given method and path requires, or null if it needs none. */
export function scopeFor(method, path) {
  return ROUTE_SCOPES[`${String(method).toUpperCase()} ${path}`] || null;
}
