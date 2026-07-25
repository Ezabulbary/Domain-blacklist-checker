# Domain Blacklist Checker

Check whether a domain, and the IPs behind its A record, are listed on spam or
malware **DNS blocklists**, with a **weighted 0-100 reputation score** and a
**removal link** for every hit.

Single and bulk checks across the full blocklist catalog, one row per list
(`LISTED / OK / TIMEOUT / SKIPPED` with reason, TTL and response time), a
one-page UI, and no login required. Each list is calibrated before its answer is
trusted, so a timeout is never reported as clean and a list that cannot answer
reliably is marked skipped instead of guessed.

### Blacklist coverage & the results table

A check resolves the domain to its IP(s) and queries **every** zone in the
catalog (`src/lib/zones.js`), IP-based lists against each A record, domain/URI
lists against the domain. Then returns a row per blacklist:

```
Checking getitok.top which resolves to 104.21.18.37 against 69 known blacklists
Listed 2 times · 24 timeout/unknown · 97 clean

STATUS    BLACKLIST        REASON                     TTL   RESP
LISTED    SURBL multi      getitok.top was listed     180   3ms
LISTED    UCEPROTECTL3     104.21.18.37 was listed    2100  22ms
OK        Spamhaus ZEN     …                          …
TIMEOUT   ivmURI (key)     requires key (unverified)  …
```

Every hostname in the catalog was **validated against live DNS** (SOA/NS + the
`127.0.0.2` test-point), not copied from a list. Each zone is tagged:

- **live**. Responds normally.
- **requiresKey**, Barracuda, Abusix, invaluement, Spamhaus (public resolver),
  Sender Score. These return a positive for *every* query when you're not
  authorized, so a "listed" answer is downgraded to **unknown** unless you opt
  in with `DBC_TRUST_KEYED=true` (i.e. you've pointed `DBC_RESOLVERS` at an
  authorized resolver / DQS). The `127.255.255.x` block sentinels are always
  treated as unknown.
- **defunct**, SORBS (shut 2024), MSRBL, DRMX, HIL/HIL2. Kept for parity; they
  answer NXDOMAIN → shown OK.
- **unverified**. Couldn't confirm from the test host; low weight so they can't
  skew the score.

Combined lists like Hostkarma use a `listedCodes` filter so their `127.0.0.1`
**whitelist** answer is never miscounted as a listing.

## What it does

```
input  →  normalize (lowercase, strip scheme/www/path, punycode,
                      public-suffix → registrable domain)
       →  DNS resolve (A, AAAA, MX)
       →  parallel fan-out:
             each IPv4  × IP blocklist zones   (reversed-octet query)
             domain     × domain blocklist zones
       →  weighted score (0–100) + verdict
       →  cache (in-memory now, Redis later)
```

A DNSBL lookup is just an `A`-record query: for IP `1.2.3.4` on
`zen.spamhaus.org` we query `4.3.2.1.zen.spamhaus.org`. A `127.0.0.x` answer
means **listed**; `NXDOMAIN` means **clean**; a timeout means **unknown**. And
unknown is never reported as clean.

## Quick start

```bash
npm install

# one-off CLI check
npm run check example.com

# bulk check from a file / stdin / args
npm run check:bulk domains.txt
cat domains.txt | npm run check:bulk
npm run check:bulk -- --csv domains.txt > report.csv

# web UI (Single + Bulk tabs) + JSON API on http://localhost:3000
npm start

# tests (pure logic, no network)
npm test
```

## HTTP API

| Endpoint | Description |
|---|---|
| `GET /api/analyze?domain=<input>` | **Full deliverability report**: risk score, auth health, blacklists, recommendations (see below). |
| `GET /api/auth?domain=<input>&selector=<sel>` | Authentication health only (SPF / DKIM / DMARC / MX / PTR). |
| `GET /api/check?domain=<input>` | Blacklist check + full results table. |
| `POST /api/check/bulk` | **Bulk check**. |
| `GET /api/zones` | The zone catalog with categories, weights + severities. |
| `GET /api/history?domain=<input>` | Stored check history (needs `DATABASE_URL`). |
| `POST /api/keys` | Generate an API key (optional; see below). |
| `GET /api/health` | Liveness + zone count. |

### API keys (optional)

The API is open by default. `POST /api/keys` (optional `{ "email": "..." }`)
returns an API key; send it as the `X-API-Key` header to authenticate. Keyed
requests get a higher rate limit (`DBC_RATE_MAX_KEYED`). Set
`DBC_REQUIRE_KEY=true` to make a key mandatory. Keys persist in the `users` table
when `DATABASE_URL` is set, otherwise they're kept in memory (lost on restart).
The web UI's **API** tab has a one-click "Generate API key" button that fills the
key into every code sample.

### Deliverability report (`/api/analyze`)

The **Analyze** tab and `/api/analyze` combine everything into one report. The
implementable slice of a full deliverability monitor:

- **Risk score (0-100) + standing**. Blends blacklist reputation (60%) and
  authentication health (40%).
- **Authentication health** (real, from live DNS):
  - **SPF**. Record, all-qualifier (`-all`/`~all`), and the 10-lookup budget.
  - **DKIM**. Probes common selectors (google, selector1/2, k1, …); pass your
    own with `?selector=`.
  - **DMARC**. Policy (`p=`), `sp`, `pct`, `rua`, alignment.
  - **MX** and **PTR/rDNS** (forward-confirmed) for resolved IPs.
  - → a 0-100 **auth score**.
- **Blacklists**. The full blocklist table, **categorized** (email / domain /
  ip / spam / malware) so the UI can filter.
- **Recommendations**. Prioritized, actionable: missing/weak SPF, DMARC
  `p=none`, no DKIM, each listing + its delist link, PTR mismatch.
- **Engagement & reputation signals** (bounce/complaint/open rate, Sender Score,
  spam traps, volume). These come from your **ESP/MTA, not DNS**, so they are
  shown as *not connected* until wired in. The report models them and lists
  their sources rather than fabricating numbers.

### Bulk check

Check a whole list in one request. The body can be:

- JSON, `{ "domains": ["a.com", "b.com"] }` or `{ "text": "a.com\nb.com" }`
- raw `text/plain` / `text/csv`. A pasted list or an uploaded `.txt`/`.csv`
  (newline-, comma-, semicolon-, tab- or space-separated; the first CSV field wins)

Add `?format=csv` to download a CSV report instead of JSON.

```bash
# JSON list
curl -X POST localhost:3000/api/check/bulk \
  -H 'content-type: application/json' \
  -d '{"domains":["google.com","example.com"]}'

# upload a file, get CSV back
curl -X POST "localhost:3000/api/check/bulk?format=csv" \
  -H 'content-type: text/csv' --data-binary @domains.txt -o report.csv
```

Bulk safeguards: inputs are **de-duped** and blanks skipped; domains are checked
with a **bounded concurrency pool** (default 5, `DBC_BULK_CONCURRENCY`) so we
don't swamp the resolver or trip DNSBL rate limits; the list is capped at
`DBC_BULK_MAX` (default 500). Each domain still benefits from the shared cache.

Response shape:

```json
{
  "ok": true,
  "summary": { "total": 2, "clean": 1, "listed": 1, "blacklisted": 0,
               "unknown": 0, "invalid": 0, "tookMs": 340 },
  "skipped": { "blank": 0, "duplicates": 0, "truncated": 0, "max": 500 },
  "results": [ { "ok": true, "domain": "…", "verdict": "…", "score": 95, … } ]
}
```

The web UI's **Bulk list** tab wraps this: paste or upload a list, get a sortable
results table (by domain / verdict / score) and a **Download CSV** button.

Example response (trimmed):

```json
{
  "ok": true,
  "domain": "example.com",
  "score": 95,
  "verdict": "listed",
  "counts": { "listed": 1, "clean": 19, "unknown": 0, "total": 20 },
  "dns": { "a": ["93.184.216.34"], "aaaa": [], "mx": [] },
  "listings": [
    {
      "zone": "multi.uribl.com",
      "subject": "example.com",
      "severity": "high",
      "meanings": [],
      "delist": "https://admin.uribl.com/"
    }
  ],
  "unknowns": []
}
```

`verdict` is one of `clean` · `listed` · `blacklisted` (a `critical`/Spamhaus
zone hit) · `unknown` (only timeouts, no definitive answer).

## Database (persistence, history, monitoring)

The app runs **DB-less by default**. Set `DATABASE_URL` to enable persistence:
every successful check is saved, `GET /api/history?domain=` reads it back, and
the schema is ready for the monitoring/alerting features on the roadmap.

```bash
# spin up local Postgres
docker compose up -d db

# apply migrations
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/blacklist npm run db:migrate

# run with persistence on
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/blacklist npm start
```

### Schema (plan §6, expanded)

PostgreSQL 13+. Migrations live in `src/db/migrations/` and are tracked in a
`schema_migrations` table by the runner.

| Table | Purpose | Key columns & rules |
|---|---|---|
| `users` | accounts / API clients | `email` (case-insensitive unique), `plan` enum `free\|pro\|agency`, auto-generated `api_key`, `updated_at` trigger |
| `domains` | every registrable domain seen | `name` unique + normalized (lowercase, no whitespace) CHECK, `first_seen`, `last_checked_at` |
| `checks` | one row per reputation check | FK→`domains` (CASCADE), FK→`users` (SET NULL, so anonymous checks persist), `score` 0–100 CHECK, `verdict` enum, full `raw_result` JSONB (GIN-indexed) |
| `monitors` | a user watching a domain | FK→`users`/`domains` (CASCADE), `frequency` enum, `active`, `next_run_at` (indexed for due-polling), unique per `(user, domain)` |
| `alerts` | recorded reputation changes | FK→`monitors` (CASCADE), `zone`, `status_change` enum `listed\|delisted`, `notified_at` outbox |

Relationships: `users 1─* checks`, `domains 1─* checks`, `users 1─* monitors *─1 domains`,
`monitors 1─* alerts`. Deleting a user cascades to their monitors and alerts but
only nulls the `user_id` on their checks (the check history for a domain is
retained).

The data-access layer is in `src/db/repositories/`. One module per table with
typed CRUD (e.g. `db.checks.saveCheck(result, { userId })`,
`db.monitors.claimDueMonitors()`, `db.alerts.recordChanges(...)`) imported via
`src/db/index.js`.

DB integration tests live in `test/db.test.js`; they **skip** unless
`TEST_DATABASE_URL` is set:

```bash
TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/blacklist_test npm test
```

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `3000` / `0.0.0.0` | Server bind. |
| `DATABASE_URL` |, | Postgres connection string. Unset = DB-less. |
| `DATABASE_SSL` | `false` | Set `true` for managed providers requiring TLS. |
| `DBC_RESOLVERS` | system | Comma-separated DNS servers. **Set this to your own recursive resolver in production** (see below). |
| `DBC_TRUST_KEYED` | `false` | Trust "listed" answers from key-required zones (set only when `DBC_RESOLVERS` is an authorized resolver / DQS). |
| `DBC_QUERY_CONCURRENCY` | `20` | Max simultaneous zone queries per check (pooled so the resolver isn't swamped). |
| `DBC_CACHE_TTL_MS` | `900000` (15 min) | Result cache TTL. |
| `DBC_RATE_MAX` / `DBC_RATE_WINDOW_MS` | `30` / `60000` | Per-IP rate limit. |
| `DBC_BULK_MAX` / `DBC_BULK_CONCURRENCY` | `500` / `5` | Bulk list cap and parallelism. |

## Critical gotchas (already handled)

These are the traps that sink most first attempts:

1. **Spamhaus blocks public resolvers.** Querying via `8.8.8.8` / `1.1.1.1`
   makes *every* domain look listed (`127.255.255.254`). We **detect that
   sentinel and downgrade the result to `unknown`**, and expose `DBC_RESOLVERS`
   so you point at your own recursive resolver (Unbound). Free
   [Spamhaus DQS](https://www.spamhaus.com/free-trial/) keys are the alternative.
2. **Timeout ≠ clean.** A query that times out or SERVFAILs is `listed: null`
   (**unknown**) and is *excluded from the score denominator*. It can never
   produce a false all-clear.
3. **Caching is mandatory, not optional.** Most DNSBLs cap free use around
   ~100k queries/day. Results are cached (in-memory MVP; swap for Redis).
4. **Rate limit your own API** so one abuser can't get your query IP blocked.
5. **Weighted scoring.** A Spamhaus hit (`weight 40`, critical) tanks the score;
   a SORBS hit (`weight 5`, informational) barely moves it.
6. **Every listing is actionable**. Each carries the list name, what the return
   code means, and a delisting link.

> **Deployment note:** cloud provider IP ranges (AWS/GCP/Azure) are themselves
> often blocked by DNSBLs. A dedicated VPS (Hetzner/OVH) with your own Unbound
> resolver is the reliable setup.

## Project layout

```
src/
  lib/
    zones.js      DNSBL zone catalog: weights, severities, return-code maps, delist links
    normalize.js  input → registrable domain (punycode, public-suffix)
    resolve.js    DNS resolution + single-zone query (timeout-safe)
    score.js      weighted 0–100 score + verdict + decorated listings
    check.js      orchestrator (normalize → resolve → fan-out → score)
    bulk.js       bounded-concurrency multi-domain check + CSV export
    auth.js       SPF / DKIM / DMARC / MX / PTR health + auth score (live DNS)
    recommend.js  rule-based, prioritized recommendations
    analyze.js    unified report: blacklists + auth + risk score + recs + signals
  db/
    pool.js       pg pool (optional; null when DATABASE_URL unset) + txn helper
    migrate.js    migration runner (tracks schema_migrations)
    migrations/   001_init.sql. The plan §6 schema
    repositories/ users, domains, checks, monitors, alerts. Typed CRUD
    index.js      barrel: import { db } from './db/index.js'
  server.js       Fastify: /api/check, /api/check/bulk, /api/history, /api/zones
  cli.js          single-domain command-line checker
  bulk-cli.js     bulk checker (file / stdin / args, --csv output)
public/
  index.html      single-page UI: Single + Bulk tabs, sortable table, CSV download
test/             node:test: normalize, score, bulk (+ db.test.js, DB-gated)
docker-compose.yml  local Postgres for development
```

## Roadmap

The MVP here is Phase 0. Planned next:

- **v1**, Redis cache, bundled Unbound resolver, Google Safe Browsing +
  URLhaus, SPF/DKIM/DMARC health score, richer delist guide.
- **v2**. Auth, bulk CSV upload, REST API keys, check history.
- **v3**. Scheduled monitoring + email/Slack alerts, PDF reports, white-label.

## License

MIT
