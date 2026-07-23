# Domain Blacklist Checker

Check whether a domain — and the IPs behind its A record — are listed on spam /
malware **DNSBLs**, with a **weighted 0–100 reputation score** and **delisting
links** for every hit.

This is the **MVP**: single-domain check, ~20 DNSBL zones across IP + domain
blocklists, a one-page UI, and no auth. It is built so the well-known DNSBL
gotchas are handled from day one (timeout ≠ clean, weighted scoring,
public-resolver detection, caching, rate limiting).

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
means **listed**; `NXDOMAIN` means **clean**; a timeout means **unknown** — and
unknown is never reported as clean.

## Quick start

```bash
npm install

# one-off CLI check
npm run check example.com

# web UI + JSON API on http://localhost:3000
npm start

# tests (pure logic, no network)
npm test
```

## HTTP API

| Endpoint | Description |
|---|---|
| `GET /api/check?domain=<input>` | Full check. Accepts URLs, `www.`, IDNs, or a bare IPv4. |
| `GET /api/zones` | The zone catalog with weights + severities. |
| `GET /api/health` | Liveness + zone count. |

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

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `3000` / `0.0.0.0` | Server bind. |
| `DBC_RESOLVERS` | system | Comma-separated DNS servers. **Set this to your own recursive resolver in production** (see below). |
| `DBC_CACHE_TTL_MS` | `900000` (15 min) | Result cache TTL. |
| `DBC_RATE_MAX` / `DBC_RATE_WINDOW_MS` | `30` / `60000` | Per-IP rate limit. |

## Critical gotchas (already handled)

These are the traps that sink most first attempts:

1. **Spamhaus blocks public resolvers.** Querying via `8.8.8.8` / `1.1.1.1`
   makes *every* domain look listed (`127.255.255.254`). We **detect that
   sentinel and downgrade the result to `unknown`**, and expose `DBC_RESOLVERS`
   so you point at your own recursive resolver (Unbound). Free
   [Spamhaus DQS](https://www.spamhaus.com/free-trial/) keys are the alternative.
2. **Timeout ≠ clean.** A query that times out or SERVFAILs is `listed: null`
   (**unknown**) and is *excluded from the score denominator* — it can never
   produce a false all-clear.
3. **Caching is mandatory, not optional.** Most DNSBLs cap free use around
   ~100k queries/day. Results are cached (in-memory MVP; swap for Redis).
4. **Rate limit your own API** so one abuser can't get your query IP blocked.
5. **Weighted scoring.** A Spamhaus hit (`weight 40`, critical) tanks the score;
   a SORBS hit (`weight 5`, informational) barely moves it.
6. **Every listing is actionable** — each carries the list name, what the return
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
  server.js       Fastify server: /api/check, /api/zones, static UI, cache, rate limit
  cli.js          command-line checker
public/
  index.html      single-page UI (score dial, listings, delist links)
test/             node:test unit tests for normalize + score
```

## Roadmap

The MVP here is Phase 0. Planned next:

- **v1** — Redis cache, bundled Unbound resolver, Google Safe Browsing +
  URLhaus, SPF/DKIM/DMARC health score, richer delist guide.
- **v2** — auth, bulk CSV upload, REST API keys, check history.
- **v3** — scheduled monitoring + email/Slack alerts, PDF reports, white-label.

## License

MIT
