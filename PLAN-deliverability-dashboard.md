# Plan — deliverability dashboard features

Reference tool = an email-deliverability monitor (Overview, Live Signals,
Blacklists, Trends, Databases, Alert Thresholds, Recommendations, History).
Splitting its features by whether we can produce **real** data:

## A. Real & implementable now (DNS / DNSBL derived) — BUILD

1. **Authentication health** — SPF, DKIM, DMARC, MX, PTR/rDNS, all from live DNS.
   - SPF: parse `v=spf1`, qualifier (`-all`/`~all`), count the 10-lookup budget.
   - DMARC: parse `_dmarc` TXT → `p`, `sp`, `pct`, `rua`, `aspf`, `adkim`.
   - DKIM: probe common selectors (google, selector1/2, k1, default, …).
   - PTR: reverse-DNS each resolved IP + forward-confirm (FCrDNS).
   - → an **auth score** (0-100).
2. **Blacklist status grid with categories + filters** — tag every zone with a
   category (email / ip / domain / spam / malware) so the UI can filter
   (All / Email / Domain-URI / IP / Spam-Phishing / Malware / Critical) and
   "show listed only". (We already query 69 zones.)
3. **Unified risk score + standing** — combine auth score + blacklist score into
   one 0-100 risk score with a GOOD/AT-RISK/POOR standing.
4. **Recommendations** — rule-based, actionable: missing/weak SPF, DMARC `p=none`,
   no DKIM, each listing + its delist link, PTR mismatch.
5. **History & Trends (real)** — from the Postgres `checks` history: chart the
   risk score, blacklist count and auth score over time (no ESP data needed).

## B. Integration-ready (needs an external/paid feed) — SCHEMA + API, labeled

Bounce rate, spam-complaint rate, open/reply rate, spam-trap hits, daily volume,
Validity Sender Score, Google Postmaster, Microsoft SNDS, Yahoo FBL. These come
from the **sender's ESP/MTA**, not from DNS — the reference tool literally labels
its Trends "Simulated". We will:
- Model them in the report + a `POST /api/signals` ingestion endpoint.
- Show them in the UI as **"not connected"** when no source is wired, with the
  source catalog (like the reference's "Signal Database Sources") — never fake
  a number and present it as real.

## C. Out of scope this pass

Auto-refresh polling, alert delivery (email/Slack), multi-tenant config UI.
(The DB already has `monitors`/`alerts` for a later monitoring worker.)

## Build order

1. `src/lib/auth.js` — SPF/DKIM/DMARC/MX/PTR + auth score (real, unit-tested).
2. `zones.js` — add `category` to all 69 zones.
3. `src/lib/recommend.js` — recommendation rules.
4. `src/lib/analyze.js` — unified report (blacklists + auth + score + recs +
   signals placeholder).
5. Server — `/api/analyze`, `/api/auth`; signals ingestion stub.
6. UI — new **Analyze** dashboard: risk gauge, auth cards, blacklist grid with
   category filters + listed-only, active listings, recommendations, and a
   clearly-labeled signals section.
7. Tests — auth parsing (fake resolver), recommendation rules, category
   integrity.
