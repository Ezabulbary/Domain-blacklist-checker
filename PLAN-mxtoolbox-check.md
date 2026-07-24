# Plan — mxtoolbox-style "check against all blacklists"

Recreate mxtoolbox's Blacklist Check: resolve a domain to its IP, query it
against **all ~68 known blacklists**, and show **every** blacklist as a row with
`LISTED / OK / TIMEOUT`, the reason (which IP/domain was listed), TTL, and
response time — plus the summary line *"Checking X which resolves to IP against
N known blacklists… Listed M times with K timeouts."*

**Our own design** — not a visual copy of mxtoolbox.

## 1. Zone catalog (the core work) — DONE (validated)

Expanded `src/lib/zones.js` from 12 → **68 zones** matching the mxtoolbox set.
Every hostname was **empirically validated against live DNS** (SOA/NS + the
`127.0.0.2` test-point), not copied from a web list:

- **live** — responds correctly (majority).
- **requiresKey** — Barracuda, Abusix, invaluement, Spamhaus-via-public-resolver,
  Sender Score. Queried anyway; a block/SERVFAIL is reported as **unknown**
  (never a false OK).
- **defunct** — SORBS (shut 2024), MSRBL, DRMX, HIL/HIL2. Kept for parity; they
  resolve NXDOMAIN → shown OK, like mxtoolbox.
- **unverified** — couldn't confirm from this host (e.g. LASHBACK, Konstant);
  low weight so they can't skew the score.

Each entry: `{ name, zone, type: ip|domain, weight, severity, note, delist,
requiresKey?, status }`. Hostkarma gets a `listedCodes` filter so its
`127.0.0.1` **whitelist** answer is not miscounted as a listing.

## 2. Engine changes

- `resolve.js` `queryZone()` — capture **TTL** (`resolve4(…, {ttl:true})`) and
  per-query **responseMs**; apply the `listedCodes`/whitelist filter.
- `check.js` — query **all** zones (IP zones × each A record, domain zones ×
  domain), return a full **per-zone result array** (listed *and* OK *and*
  timeout), plus `resolvesTo`, `zonesChecked`, `listedCount`, `timeoutCount`.
- `score.js` — unchanged weighting; expose `timeouts` count.

## 3. Surfaces

- **UI** — a new full-width results table (all 68 rows): status badge, blacklist
  name (+ delist link when listed), reason, TTL, response time; summary header
  with the resolve-to IP and *listed/timeout* counts. Our own design.
- **CLI** — `check` prints the full table; keeps the summary line.
- **API** — `/api/check` returns the richer object (back-compatible fields kept).

## 4. Tests

Extend `zones`/engine tests: catalog integrity (unique zones, valid types,
weights), TTL/responseMs presence, hostkarma whitelist handling, and the
all-zones result shape. Live-DNS smoke test stays opt-in.

## 5. Out of scope (this pass)

Per-list historical detail pages, "Solve email delivery" wizard, monitoring
(already have the DB for it). Focus is the all-blacklists check + result table.
