# Architecture

Ei document e: code ta kivabe sajano, ekta request kivabe kaj kore, kon file er
ki dayitto, ar kon file gulo cholate lage vs lage na.

---

## 1. Layer (upor theke niche)

```
  ┌──────────────────────────────────────────────────────────────┐
  │  ENTRY POINTS                                                │
  │  server.js        HTTP API + web UI                          │
  │  cli.js           single domain check (terminal)             │
  │  bulk-cli.js      many domains (file / stdin)                │
  │  calibrate-cli.js blocklist trust report                     │
  │  db/migrate.js    database migrations                        │
  └───────────────────────────┬──────────────────────────────────┘
                              │
  ┌───────────────────────────▼──────────────────────────────────┐
  │  ORCHESTRATION   analyze.js   full report (score+auth+recs)   │
  │                  bulk.js      many domains, bounded pool      │
  └───────────────────────────┬──────────────────────────────────┘
                              │
  ┌───────────────────────────▼──────────────────────────────────┐
  │  DOMAIN LOGIC                                                 │
  │  check.js      one domain: normalize, resolve, query, score   │
  │  auth.js       SPF / DKIM / DMARC / MX / PTR health           │
  │  calibrate.js  which blocklists can be trusted from here      │
  │  recommend.js  findings  ->  prioritized actions              │
  │  score.js      weighted 0-100 reputation score                │
  └───────────────────────────┬──────────────────────────────────┘
                              │
  ┌───────────────────────────▼──────────────────────────────────┐
  │  PRIMITIVES (no app logic, easy to test)                      │
  │  zones.js      the blocklist catalog + answer-code rules      │
  │  resolve.js    DNS: resolver, one zone query, TTL + timing    │
  │  normalize.js  raw input  ->  registrable domain              │
  │  env.js        load .env                                      │
  │  apikeys.js    create / validate API keys                     │
  └───────────────────────────┬──────────────────────────────────┘
                              │ (optional)
  ┌───────────────────────────▼──────────────────────────────────┐
  │  PERSISTENCE (only when DATABASE_URL is set)                  │
  │  db/pool.js  db/index.js  db/repositories/*  db/migrations/*  │
  └──────────────────────────────────────────────────────────────┘
```

**Niyom:** upor er layer niche ke call kore, ulta kokhono na. `zones.js`,
`normalize.js`, `resolve.js` kono kichu import kore na, tai egulo alada kore
test kora jay.

---

## 2. Ekta request kivabe cholе (`GET /api/analyze?domain=x.com`)

```
  server.js
    │  1. auth check (X-API-Key, optional)  ->  apikeys.js
    │  2. rate limit (per IP or per key)
    ▼
  analyze.js
    │
    ├──►  check.js ─────────────────────────────────────────────┐
    │       1. normalize.js   "https://WWW.X.com/a"  ->  x.com   │
    │       2. resolve.js     A / AAAA / MX records              │
    │       3. calibrate.js   kon list trust kora jabe?          │
    │       4. resolve.js     trusted list gulo query (pool)     │
    │       5. retry pass     transient timeout gulo abar        │
    │       6. collapse       ek blocklist = ek row              │
    │       7. score.js       weighted 0-100                     │
    │                                              ◄─────────────┘
    ├──►  auth.js       SPF / DKIM / DMARC / MX / PTR  ->  auth score
    │
    ├──►  riskScore()   blocklist 60% + auth 40%
    │
    └──►  recommend.js  findings  ->  ki korte hobe (priority soho)

  server.js  ->  cache (memory)  ->  optional save (db)  ->  JSON
```

Frontend (`public/index.html`) ei JSON ta render kore. Kono build step nai,
kono framework nai, ekta file.

---

## 3. Kon file ki kore

### Entry points
| File | Kaj |
|---|---|
| `src/server.js` | Fastify server: sob API route, static UI, cache, rate limit, API-key auth |
| `src/cli.js` | `npm run check <domain>` |
| `src/bulk-cli.js` | `npm run check:bulk <file>` |
| `src/calibrate-cli.js` | `npm run calibrate` (trust report) |
| `src/db/migrate.js` | `npm run db:migrate` |

### Orchestration
| File | Kaj |
|---|---|
| `src/lib/analyze.js` | Puro report: blocklist + auth + risk score + recommendations |
| `src/lib/bulk.js` | Onek domain, bounded concurrency, CSV export |

### Domain logic
| File | Kaj |
|---|---|
| `src/lib/check.js` | Ekta domain er puro blocklist check (ei project er core) |
| `src/lib/calibrate.js` | Protita list ke live probe kore bole: trust kora jabe kina |
| `src/lib/auth.js` | SPF, DKIM, DMARC, MX, PTR + auth score |
| `src/lib/recommend.js` | Rule-based suggestion (pure function, no I/O) |
| `src/lib/score.js` | Weighted 0-100 score + verdict |

### Primitives
| File | Kaj |
|---|---|
| `src/lib/zones.js` | 69 blocklist er catalog, weight, category, test point, DQS key handling |
| `src/lib/resolve.js` | DNS resolver toiri, ekta zone query (TTL + response time soho) |
| `src/lib/normalize.js` | Input parse: scheme/www/path bad, punycode, registrable domain |
| `src/lib/env.js` | `.env` load kore |
| `src/lib/apikeys.js` | API key banano ar validate |

### Persistence (optional)
| File | Kaj |
|---|---|
| `src/db/pool.js` | Postgres pool (DATABASE_URL na thakle `null`), TLS, transaction |
| `src/db/index.js` | Ek jaygay sob repository (`db.checks`, `db.users`, ...) |
| `src/db/repositories/*.js` | users, domains, checks, monitors, alerts er CRUD |
| `src/db/migrations/001_init.sql` | Table, index, constraint |

### Frontend
| File | Kaj |
|---|---|
| `public/index.html` | Puro UI: Analyze, Bulk list, API tab. HTML + CSS + JS ek file e |

---

## 4. Guruttopurno design decision

**1. Calibration age, tarpor result.**
Kono blocklist er answer tokhon-i gona hoy jokhon se **proman kore** je se
amader thik uttor dey (test point listed + control clean)। Jara shobaike
"listed" bole ba chup kore ignore kore, tader bad deoa hoy. Bishod: `ACCURACY.md`।

**2. Ek blocklist = ek row.**
Domain er 3 ta IP thakle-o ekta list ekbar-i gona hoy (worst state wins)। Tai
`listed + clean + timeout + skipped` shob somoy catalog size er soman.

**3. Timeout kokhono "clean" na.**
Uttor na pele "unknown" bola hoy, guess kora hoy na.

**4. DB optional.**
`DATABASE_URL` na dile pool `null` thake ar app puro cholte thake. History ar
monitoring sudhu DB thakle.

**5. Secret leak na.**
Spamhaus DQS key sudhu DNS query banate use hoy (`queryHost`), API/UI te
public `zone` naam-i jay. Test diye guard kora.

---

## 5. Cholate ki ki lage (ar ki lage na)

### Obosshoi lagbe (runtime)
```
package.json  package-lock.json
src/          (sob)
public/index.html
```
Sudhu ei gulo diye `npm install && npm start` cholbe.

### Config
```
.env              tomar setting (resolver, DQS key, port)
.env.example      reference
```

### Deploy (dorkar hole)
```
Dockerfile  .dockerignore     Docker diye deploy
docker-compose.yml            local Postgres (DB use korle)
```

### Lage na (development ar documentation)
```
test/             quality safety net. Cholate lage na, kintu na rakhle
                  bhobishyote change korle bug dhora porbe na
README.md  GETTING-STARTED.md  ACCURACY.md  ARCHITECTURE.md
.gitignore
```

### Nije toiri hoy (delete kora jay, abar banabe)
```
node_modules/        npm install
.calibration.json    npm run calibrate (ba prothom check)
```

> **Minimal runtime bundle** banate chaile: `package.json`, `package-lock.json`,
> `src/`, `public/`, `.env` rakho. Baki sob bad dile-o tool cholbe.
> Tobe `test/` bad deoar age vebe nio: oita-i dhore je notun change kichu
> bhange nai (`npm test`, 53 ta test)।

---

## 6. Sonkha (ekhon)

| | |
|---|---|
| Runtime source file | 23 (`src/`) + 1 (`public/index.html`) |
| npm dependency | 4 (`fastify`, `@fastify/static`, `tldts`, `pg`) |
| Test | 53 pass |
| Blocklist catalog | 69 |
