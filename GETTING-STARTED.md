# Getting Started — A to Z (ki ki korte hobe)

Domain Blacklist Checker cholanor jonno step-by-step guide. Command gulo English e,
bujhano Bangla te.

---

## 0. Ki lagbe (prerequisite)

- **Node.js 18 or newer** (tomar kache 24 ache — perfect).
  Check koro:
  ```
  node --version
  ```
  Jodi na thake: https://nodejs.org theke LTS version install koro.

- Database (Postgres) **optional** — chara-o app cholbe. (Niche §4 dekho.)

---

## 1. Project ta ready koro

1. Zip ta **unzip** koro ekta folder e (jemon `D:\scratch\Domain blacklist checker`).
2. Terminal / Command Prompt kholo, oi folder e jao:
   ```
   cd "D:\scratch\Domain blacklist checker"
   ```

---

## 2. Dependencies install koro  ⚠️ (ei step ta miss korle "Cannot find package 'pg'" error ashbe)

```
npm install
```

- Eta `pg`, `fastify`, `@fastify/static`, `tldts` — sob download kore `node_modules/` folder e rakhe.
- **Prottekbar notun kore unzip korle ekbar `npm install` lagbe** (node_modules zip e thake na).
- Ekbar install hoye gele barbar lagbe na.

---

## 3. App chalao (DB chara — shobcheye shohoj)

```
npm start
```

- Terminal e dekhabe server `http://localhost:3000` e cholche.
- **Browser e kholo:** http://localhost:3000
- Bondho korte: terminal e `Ctrl + C`.

### Browser e ki korbe
- **Analyze tab** — ekta domain lekho (jemon `github.com`) → **Analyze** cap dao.
  Pabe: risk score, SPF/DKIM/DMARC health, recommendations, ar 69 blacklist er full table.
- **Bulk list tab** — onek domain ekshathe (each line e ekta), ba ekta `.txt`/`.csv`
  upload koro → **Check all** → result table + **Download CSV**.
- **API tab** — tomar nijer app/script theke ei tool use korte chaile ready code
  copy koro: cURL, JavaScript, Python, PHP, Go, Ruby, Java, C# — protita endpoint er
  jonno. Kono API key lage na.

### Command line theke o cholbe (server chara)
```
npm run check github.com          # ekta domain
npm run check github.com -- --all # shob list dekhao
npm run check:bulk domains.txt    # file theke bulk
```

---

## 4. Database setup (OPTIONAL — history/monitoring lagle)

DB chara-o blacklist check, analyze, bulk — sob kaj kore. DB sudhu **check history save**
ar future monitoring er jonno lage.

### 4a. Postgres install (jekono ekta)
- **Docker diye (shohoj):** project e `docker-compose.yml` ache —
  ```
  docker compose up -d db
  ```
- **Othoba** local Postgres install kore ekta database banao (jemon `blacklist`).

### 4b. Migration chalao (table gulo banabe)
`DATABASE_URL` set kore migrate koro:

**Windows (Command Prompt):**
```
set DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/blacklist
npm run db:migrate
npm start
```
**Windows (PowerShell):**
```
$env:DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5432/blacklist"
npm run db:migrate
npm start
```
**Mac/Linux:**
```
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/blacklist npm run db:migrate
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/blacklist npm start
```

DB on thakle `/api/health` e `"db":true` dekhabe, ar protita check DB te save hobe.
History dekhte: `http://localhost:3000/api/history?domain=github.com`.

---

## 4c. `.env` file — ekbar set, barbar na (tomar prosno)

**Protibar `set DBC_RESOLVERS=...` type korte hobe NA.** Project e ekta `.env`
file ache — app start howar somoy eta **nije-i porhe**. Tate already ache:
```
DBC_RESOLVERS=1.1.1.1
```
Tai tumi sudhu `npm start` dilei cholbe. Kichu poriborton korte chaile — jemon
onno resolver ba `DATABASE_URL` — `.env` file ta **text editor e kholo, value
paltao, save koro, restart koro**. Bas. (Command prompt e set korle-o hobe, kintu
`.env` beshi shohoj.)

---

## 5. Production e valo result er jonno (important)

Ei tool DNS query kore. **Public resolver (8.8.8.8 / 1.1.1.1) Spamhaus block kore**, ar
onek list e key lage — tai default e oi list gulo "timeout/unknown" dekhabe (fake "clean" na,
eta thik). Real result er jonno:

- **Nijer recursive resolver (Unbound)** chalao, ar tar IP dao:
  ```
  set DBC_RESOLVERS=127.0.0.1
  ```
- Spamhaus/Barracuda/Abusix er **free key / DQS** thakle:
  ```
  set DBC_TRUST_KEYED=true
  ```
  (tokhon key-required list er result-o trust korbe)

Local e (nijer laptop e) test korle onek list timeout dekhabe — eta normal, code er dosh na.

---

## 6. Shob command (cheat sheet)

| Command | Ki kore |
|---|---|
| `npm install` | Dependencies install (prothome ekbar) |
| `npm start` | Web server + UI (http://localhost:3000) |
| `npm run dev` | Same, kintu file change e auto-restart |
| `npm run check <domain>` | CLI single check |
| `npm run check <domain> -- --all` | Shob list soho |
| `npm run check:bulk <file>` | CLI bulk (file/stdin) |
| `npm run check:bulk -- --csv <file>` | Bulk → CSV output |
| `npm run db:migrate` | DB table banao (DATABASE_URL lage) |
| `npm run calibrate` | Kon blacklist trust kora jay — live test kore report dey |
| `npm test` | Sob test chalao |

## 7. Shob setting (environment variable — optional)

| Variable | Default | Kaj |
|---|---|---|
| `PORT` / `HOST` | 3000 / 0.0.0.0 | Server address |
| `DBC_RESOLVERS` | system | Nijer DNS resolver (production e set koro) |
| `DBC_TRUST_KEYED` | false | Key-required list er result trust korbe |
| `DBC_QUERY_CONCURRENCY` | 20 | Ek shathe koto DNS query |
| `DBC_CACHE_TTL_MS` | 900000 | Cache koto khon (15 min) |
| `DBC_RATE_MAX` | 30 | Per-IP per-minute limit |
| `DATABASE_URL` | — | Postgres connection (set korle DB on) |

Puro list `.env.example` file e ache.

---

## 8. Troubleshooting (samasya hole)

| Error / Samasya | Karon + Fix |
|---|---|
| `Cannot find package 'pg'` | `npm install` chalao nai. Chalao. |
| **Onno site (mxtoolbox) er sathe result mile na** | App ekhon **nije test kore** kon list bishwasjoggo (`npm run calibrate`)। Je list amader mittha uttor dey (jemon invaluement — shobaike "listed" bole) ba chup kore ignore kore (Spamhaus, public resolver theke), segulo **SKIPPED** dekhabe — score e dhora hoy na. Puro bishleshon: **`ACCURACY.md`**. |
| **Shob domain "same"/faka result, "resolves to —", A/MX faka, 0 clean** | Tomar machine e **DNS kaj korche na** — kono domain resolve hocche na. Fix: `set DBC_RESOLVERS=1.1.1.1` diye `npm start` (PowerShell: `$env:DBC_RESOLVERS="1.1.1.1"`). Tao na hole network/firewall DNS (port 53) block korche — onno network e cheshta koro. UI ekhon ekta warning banner-o dekhabe. |
| `npm start` e port busy (`EADDRINUSE`) | Onno kichu 3000 port e cholche. `set PORT=3001` diye chalao. |
| Onek list "TIMEOUT" dekhachche | Normal — public resolver + key nai. §5 dekho. |
| `history requires DATABASE_URL` | DB set kora nai. §4 dekho (ba history bad dao). |
| `db:migrate` e connection refused | Postgres cholche na / DATABASE_URL bhul. §4 dekho. |
| DKIM "NONE" but domain er DKIM ache | Selector janle: `/api/auth?domain=x.com&selector=<selector>` |

---

## 9. Concept bujho (kichu common prosno)

**"Timeouts are reported as unknown, never as clean. Weighted score:
Spamhaus > Barracuda > SORBS." — ei line er mane ki?**
- Ekta blacklist ke jiggesh korle 3 rokom uttor hote pare: **CLEAN** (listed na),
  **LISTED** (ache), ba **kono uttor nai** (timeout).
- Onek tool timeout ke bhul kore "clean" dhore ney. **Amra ta kori na** — timeout
  hole **"unknown"** dekhai, karon uttor na pele "clean" bola bhul.
- **Weighted score** = shob list er weight soman na. **Spamhaus** (shobcheye
  important) e listed hole score onek nambe; **Barracuda** majhari; **SORBS**
  (informational, ekhon defunct) khub kom effect. Tai final score ekta list er
  gurutto onujayi hisheb hoy.

**TIMEOUT ar SKIPPED — parthokko ki? (tomar prosno: timeout keno hoy)**
Ekhon **timeout prai 0** dekhabe. Ki kore korlam:
- Je list gulo query korle uttor dey (live), tara timeout hole **nije theke retry**
  hoy — tai slow-but-alive list-o uttor dey.
- Je list gulo **bondho (defunct)** — SORBS, MSRBL, DRMX, HIL — ba **key/nijer
  resolver chara uttor dey na** (Spamhaus, Barracuda, Abusix, invaluement, SpamRats)
  — segulo ke amra **query-i kori na**. Egulo **"SKIPPED"** dekhabe ("list inactive"
  ba "needs key"), **TIMEOUT na**. Karon mora list e query kore timeout dekhano
  ortho-hin.
- Result e ekhon: **Listed / Clean / Timeout (~0) / Skipped**.

**Skipped list gulo-o cek korte chao?** (jemon Spamhaus, SpamRats)
- Egulor jonno **nijer recursive resolver (Unbound)** ba **Spamhaus free DQS key**
  lage. Setup kore `.env` e dao:
  ```
  DBC_RESOLVERS=127.0.0.1
  DBC_TRUST_KEYED=true
  ```
  Tokhon oi list gulo-o query hobe (mxtoolbox er moto — karon tader-o authorized
  access ache)।

> **Mne rakho:** TIMEOUT = "janina" (CLEAN na). SKIPPED = "cek korini" (dead/key lage).
> Duita-i honest — kono list ke bhul kore "clean" boli na.

**`.env` file e ki korte hobe?**
- Kichu na — already `DBC_RESOLVERS=1.1.1.1` set kora ache, app cholbe.
- Sudhu jodi onno resolver/DB/setting lage, tokhon `.env` edit korba (§4c).

---

## 10. Result 100% thik kina kivabe bujhba (verify)

Ei tool kono kichu "guess" kore na — protita LISTED/CLEAN holo ekta **real DNS
answer**:
- **LISTED** = oi blacklist `127.0.0.x` return koreche (definitively listed).
- **CLEAN** = NXDOMAIN return koreche (definitively listed na).
- **TIMEOUT** = kono uttor pai nai (guess kori na).
- **SKIPPED** = query-i korini (dead / key lage).

Tumi nijei ei result **nijer terminal e verify korte paro** (`nslookup` diye —
Windows/Mac/Linux sob tei ache):

**1) IP listing verify (reverse the IP + `.` + zone):**
`104.21.18.37` listed on `dnsbl-3.uceprotect.net` dekhale — IP ta ulta koro
(`104.21.18.37` → `37.18.21.104`) ar zone judo:
```
nslookup 37.18.21.104.dnsbl-3.uceprotect.net
```
`127.0.0.x` ashle = LISTED (tool thik). "Non-existent domain" ashle = clean.

**2) Domain listing verify (domain + `.` + zone):**
```
nslookup getitok.top.multi.surbl.org
```
`127.0.0.x` = listed.

**3) SPF / DMARC verify:**
```
nslookup -type=txt example.com          (SPF — v=spf1 … dekhbe)
nslookup -type=txt _dmarc.example.com   (DMARC — v=DMARC1; p=… dekhbe)
```

**4) Onno tool er sathe cross-check:**
Same domain https://mxtoolbox.com/blacklists.aspx e dao — LISTED gulo mile jabe
(je list dutai query kore)। Parthokko sudhu: mxtoolbox er kache Spamhaus/Barracuda
er **paid/authorized access** ache, tai tara oi list gulo-o dekhay; amader default
e segulo **SKIPPED** (nijer resolver + `DBC_TRUST_KEYED=true` dile amra-o dekhabo)।

**5) Delist link:**
Protita LISTED row e ekta **"Delist →"** link ache — seta oi list er **nijer
official lookup page** e niye jay, jekhane source theke confirm korte parba.

**6) Automated test:** `npm test` → **48 test pass** (logic verify kora)।

> Short kotha: LISTED/CLEAN = DNS er confirmed answer, amar banano number na.
> Upor er `nslookup` command diye nijei melate parba.

---

## Kono ekta step atke gele oi terminal output ta paste koro — dekhe debo.
