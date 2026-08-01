# Architecture

Ei document ta ekta nirdishto workflow er jonno sajano:

> **10,000+ domain database e ache. Protita domain din e 2 bar automatic check
> hobe. Kono domain listed dhora porle client ke message jabe, ar CC te jabe
> super admin, admin, ar oi client jar under e ase (account manager)।**

Niche: purono architecture ei kaje keno bhangbe, notun ta ki, sweep kivabe
chole, kokhon alert jabe ar kokhon jabe na, ke ke pabe, ar sonkha gulo ki bole.

---

## 1. Purono architecture ta ei kaje keno cholbe na

Ekhon jeta ache seta **request-driven**: keu UI/API te ekta domain dey, tokhon
check hoy, result feriye dey. Sob kaj ekta HTTP request er bhitore.

Ei workflow e sheta 4 jaygay bhangbe:

| Somossa | Keno |
|---|---|
| **Kaj ta 90 minute er** | 10,000 domain ek sweep e ~90 minute (mepe dekha). HTTP request 5 minute-o benche thake na. Ei kaj **background e** cholte hobe, request er bhitore na. |
| **Alert er kono dharona nai** | Ekhon protita check ekta sadharon result. "Age clean chilo, ekhon listed" ei **poriborton** ta kothao dhora pore na. Alert lagbe poriborton e, obosthay na. Nahole din e 2 bar kore eki listing er jonno message jabe, chirokal. |
| **Ke ke jante parbe, seta nai** | Ekhon `users` ache, kintu **client**, **account manager**, **admin**, **super admin** ei kathamo nai. CC korar jonno ei somporko ta lagbe. |
| **Ek sweep e 1.8 million DNS query** | Ei volume public resolver theke kora **osombhob**. Nijer resolver lagbe, ar sathe **IP dedup** na korle DQS quota-o shesh hoye jabe. |

Tar mane baki code ta phele dite hobe na. `check.js`, `zones.js`, `calibrate.js`,
`score.js`, `resolve.js` ei core ta ekdom thik ache ar oitai engine er bhitore
boshbe. Uporer layer ta notun kore banate hobe.

---

## 2. Notun architecture, ek nojore

```
   ┌──────────────┐        ┌──────────────────────────────────────────┐
   │  SCHEDULER   │        │  Din e 2 bar sweep toiri kore            │
   │  (cron)      │───────►│  06:00 ar 18:00 (config kora jay)        │
   └──────────────┘        │  10,000 domain queue e dhukiye dey       │
                           └────────────────┬─────────────────────────┘
                                            │
                    ┌───────────────────────▼───────────────────────┐
                    │  sweep_jobs  (Postgres queue)                  │
                    │  FOR UPDATE SKIP LOCKED                        │
                    └───────────────────────┬───────────────────────┘
                                            │
        ┌───────────────┬───────────────────┼───────────────────┐
        ▼               ▼                   ▼                   ▼
   ┌─────────┐    ┌─────────┐         ┌─────────┐         ┌─────────┐
   │ WORKER 1│    │ WORKER 2│   ...   │ WORKER N│         │ (scale  │
   └────┬────┘    └────┬────┘         └────┬────┘         │  kora   │
        │              │                   │              │  jay)   │
        └──────────────┴─────────┬─────────┘              └─────────┘
                                 │ protita worker:
                                 │   check.js  ->  IP cache  ->  DNS
                                 ▼
                    ┌────────────────────────────┐
                    │  STATE ENGINE              │
                    │  age ki chilo vs ekhon ki  │
                    │  poriborton hole incident  │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │  SAFETY GATE               │
                    │  sweep ta bishwasjoggo?    │
                    │  na hole notification BONDHO│
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │  NOTIFIER                  │
                    │  ke pabe -> message banao  │
                    │  -> outbox -> pathao       │
                    └────────────────────────────┘
```

**Purono layer gulo (`analyze.js`, `check.js`, `zones.js`, ...) ekhon-o ache**,
sudhu tara ekhon HTTP request er niche na, **worker er niche** boshe.

---

## 3. Ekta sweep kivabe chole (puro path)

```
06:00  SCHEDULER
  │
  ├─ 1. CALIBRATE. Sob blocklist ke live probe kore: kake trust kora jay?
  │     (ei sweep er jonno ekbar, protita domain er jonno na)
  │
  ├─ 2. SANITY GATE #1. Trusted zone koyta?
  │       36 er niche  ->  sweep BATIL. Ops ke alert. Client ke kichu na.
  │       karon: resolver bhanga obosthay check korle hoy sob "clean"
  │       dekhabe (asol listing miss hobe), noy sob "listed" (10,000
  │       client ke mittha message jabe). Duitai bhoyaboho.
  │
  ├─ 3. QUEUE. active domain gulo sweep_jobs e dhukiye dey (10,000 row)
  │     window e chhoriye dey, ek shathe sob na
  │
  ▼
WORKER (N ta, parallel)
  │
  ├─ 4. CLAIM. FOR UPDATE SKIP LOCKED diye ekta job neya
  │
  ├─ 5. RESOLVE. domain -> A record (max 2 IP)
  │
  ├─ 6. IP CACHE dekha. Ei IP er 55 ta IP-zone er uttor ki ei sweep e
  │     age keu nishe? Nile DNS e jaoa lagbe na. (dekho §7, eta-i
  │     shobcheye boro sasroy)
  │
  ├─ 7. QUERY. trusted zone gulo (pool, 12 at a time) + retry pass
  │
  ├─ 8. SCORE. ek blocklist = ek row, weighted 0-100, verdict
  │
  ├─ 9. SAVE. checks table e raw result
  │
  ▼
STATE ENGINE  (protita domain er por por)
  │
  ├─ 10. protita (domain, zone) er **age ki chilo** vs **ekhon ki**
  │      clean -> listed   :  CONFIRM koro, tarpor incident OPEN
  │      listed -> clean   :  incident CLOSE
  │      listed -> listed  :  kichu na (open incident tader jonno)
  │      jekono -> timeout :  **kichu na**, purono state thake
  │
  ▼
SWEEP SHESH
  │
  ├─ 11. SANITY GATE #2. Ei sweep e notun listing koyta?
  │        age er sweep er 5 gun er beshi, ba sob domain er 5% er beshi
  │        ->  notification HOLD. Ops review korbe, tarpor release.
  │
  ▼
NOTIFIER
  │
  ├─ 12. Client onujayi jorabe. Ek client er 12 ta domain listed hole
  │      **12 ta message na, 1 ta message** e 12 tar list.
  │
  ├─ 13. Recipient ber kora: To = client, CC = account manager, admin,
  │      super admin
  │
  └─ 14. outbox e likhe dey  ->  delivery worker pathay  ->  fail hole retry
```

---

## 4. State engine. Kokhon alert jabe, kokhon jabe na

Eta-i ei workflow er **sob theke joruri ongsho**. Bhul hole hoy client alert
paabe na, noy roj roj faltu message paabe.

### Niyom: alert hoy **poriborton** e, obosthay na

Protita `(domain, zone)` jorar ekta current state DB te thake
(`domain_zone_state` table)। Notun result ashle purono tar sathe milano hoy:

| Age | Ekhon | Ki hobe |
|---|---|---|
| clean | **listed** | CONFIRM koro. Confirm hole **incident OPEN + notify** |
| listed | listed | Kichu na. Incident already open |
| listed | **clean** | Incident CLOSE + "thik hoye geche" notify |
| clean | clean | Kichu na |
| jekono | **timeout / unknown** | **Kichu na.** Purono state ojotha thake, ar `unknown_since` marka pore |
| jekono | skipped (untrusted list) | Kichu na |

**Timeout kokhono state bodlay na.** Uttor na pawa mane "clean hoye geche" na,
"listed hoye geche"-o na. Eta age theke-i tool er niyom (`ACCURACY.md`), ekhon
alert-er khetreo eki niyom.

### CONFIRM step. Ekta bhul uttor e 4 jon ke jagabe na

Notun listing dhora porle **shonge shonge abar query kora hoy**, oi ekta
`(domain, zone)` jora, **alada resolver diye**. Duibar-i "listed" bolle tobe-i
incident khole.

Keno dorkar: ekta transient bhul uttor e client + account manager + admin +
super admin, char jon message pabe. Ekbar hole tara tool ta bishwas korbe na.
Ei extra query ta ekta sweep e maximum kek shoto ta, mane khoroch nai bollei
chole.

> **Keno porer sweep porjonto opekkha kori na?** Karon porer sweep 12 ghonta
> pore. Asol listing 12 ghonta chapa thakle mail delivery mora jabe. Tai
> confirmation shonge shonge, opekkha kore na.

### Flap protection

Ekta list jodi bar bar list kore ar sorai (flapping), tahole:
- **72 ghontar bhitore** eki `(domain, zone)` er incident abar khulle **notun
  message jay na**, purono incident e `flap_count` bare.
- 3 bar flap korle incident ta `noisy` mark hoy ar oi zone ta oi domain er jonno
  auto-suppress hoy, ops ke ekbar jananor por.

### Prothom sweep alada (baseline mode)

Prothom bar cholar shomoy database e kono purono state nai, tai **10,000 domain
er protita listing "notun"** mone hobe. Tokhon jodi notify kore, prothom din-i
kek sho client ke ekshathe message jabe.

Tai prothom sweep `baseline` mode e chole: **state likhe rakhe, kono
notification pathay na**, ar shesh e ekta summary report dey ("ekhon 214 ta
domain listed")। Tarpor theke sudhu poriborton e alert.

Ei mode ta notun client onboard korar shomoy-o lage: notun client er domain
gulor prothom check baseline, tarpor theke alert.

---

## 5. Notification. Ke pabe, kototuku pabe

### Recipient

Ekta listing client X er domain e hole:

```
  To  :  client X er notify contact (ek ba onek)
  CC  :  client X er account manager  (jar under e client ta)
  CC  :  admin       (role = 'admin')
  CC  :  super admin (role = 'super_admin')
```

Ei somporko ta DB te:

```
  clients            ekta client / company
  users              role: 'super_admin' | 'admin' | 'account_manager' | 'client_user'
  client_managers    kon manager kon client er under e (many-to-many)
  client_contacts    client er kon address e message jabe
```

### Batching. Eta na korle system ta obabohar joggo hobe

10,000 domain e ekdin e 200 ta notun listing hote pare (jemon ekta boro
provider block hole)। Domain prati ekta message pathale:

```
  200 message  ×  4 jon (client + manager + admin + super admin)  =  800 delivery
```

Tar bodole **client prati ekta message per sweep**:

```
  200 listing  ->  jodi 40 ta client e chhorano  ->  40 message
```

Message er bhitore oi client er sob domain er table. Ei ta default.

### Volume niyontron (admin ke daabate na deoar jonno)

Client ar account manager er kache **protita incident** jaowa thik ache. Kintu
admin ar super admin **sob client er sob incident** paay, mane ekdin e kek sho
message. Tai protita recipient er ekta `delivery_mode`:

| Mode | Kar jonno | Ki paay |
|---|---|---|
| `immediate` | client, account manager | Protita sweep er notun listing shonge shonge |
| `digest` | admin, super admin (suggest kora) | Din e ekbar, sob client er sob kichu ek message e |
| `critical_only` | jara sudhu boro jinis chan | Sudhu Spamhaus (`blacklisted`), baki na |

Tumi chaile admin/super admin ke `immediate` e rakhte paro (tomar workflow e
CC-i bola ache, tai **default `immediate`**)। Kintu volume beshi mone hole
`digest` e sorano jay, code bodlate hobe na.

### Severity onujayi urgency

`score.js` er verdict ekhane sorasori kaje lage:

| Verdict | Mane | Default action |
|---|---|---|
| `blacklisted` | Spamhaus ZEN / DBL | **Shonge shonge**, sob recipient ke |
| `listed` (high severity zone) | Barracuda, SpamCop, SURBL | Shonge shonge |
| `listed` (low severity zone) | ZapBL, UCEPROTECT L3 ityadi | Daily digest e |

Ei bhagta config kora jay. Karon ZapBL e thakle keu mail block kore na, kintu
Spamhaus e thakle mail bounce kore. Duitar jonno eki alarm bajale asol tar
gurutto hariye jabe.

### Outbox pattern

Message DB te likha hoy **age**, pathano hoy **pore**:

```
  notifications           ek message (client, sweep, koyta listing)
  notification_recipients ke ke pabe, kar kon mode
  notification_deliveries protita pathanor chesta: status, attempt, error
```

Keno: SMTP fail korle ba process restart hole message harabe na. `pending`
row gulo abar chesta hobe (exponential backoff)। Ar `idempotency_key`
(sweep_id + client_id) thakay **eki message duibar jabe na**.

### Channel

Ekhon **email** first-class. Kintu notifier er bhitore ekta chhoto interface:

```js
  send({ to, cc, subject, body }) -> { messageId }
```

Email adapter ta prothom. Pore WhatsApp / SMS / Slack / in-app lagle **notun
ekta adapter**, baki kono code bodlabe na. Recipient table e `channel` column
ache, tai ekjon email e ar arekjon WhatsApp e pete pare.

---

## 6. Safety gate. 10,000 client ke mittha message pathano thekano

Ei scale e shobcheye boro bipod bug na, **bhul data**. Duita obostha:

1. **Resolver mora / block** → sob domain "clean" dekhabe → asol listing miss
   hobe, keu janbe na.
2. **Kono list shobaike "listed" bolche** (jemon invaluement era kore, dekho
   `ACCURACY.md` §1) → **10,000 client ke mittha message** jabe.

Tai duita gate:

**Gate 1, sweep shuru howar age.** Calibration cholbe. Trusted zone count
threshold er niche hole (default 36) sweep-i cholbe na. Ops alert pabe.

**Gate 2, notification pathanor age.** Ei sweep er notun listing count:

```
  age er sweep er 5 gun er beshi?           -> HOLD
  ba, sob active domain er 5% er beshi?     -> HOLD
```

HOLD mane: incident gulo DB te thakbe, `notifications` row toiri hobe, kintu
`status = 'held'`। Ops dashboard e dekhbe, thik mone hole ek click e release,
bhul mone hole batil. **Manush ekbar dekhbe, tarpor 10,000 message jabe.**

Ei gate ta na thakle ekta bhul calibration ekdin er moddhe tomar sob client er
kache tomar tool er bishwasjogyota shesh kore dite pare.

---

## 7. Sonkha. Ei load ta asole koto

### Somoy (ei codebase e mepe dekha)

| Ki | Mapa | 10,000 domain e |
|---|---|---|
| Blocklist only, concurrency 5 | 111 domain/min | **90 minute** |
| Blocklist only, concurrency 20 | 140 domain/min | **71 minute** |
| Blocklist + auth, concurrency 5 | 60 domain/min (479 domain = 477s) | **167 minute** |

Din e 2 bar, blocklist only, concurrency 20 → **din e prai 2.4 ghonta**. Ekta
sadharon VPS e eta bhalo vabe cholbe, headroom-o thakbe.

> **Suggestion: auth (SPF/DKIM/DMARC) din e 2 bar cholano ojotha.** SPF/DKIM/
> DMARC record maase ekbar-o bodlay na, kintu blacklist status ghontay bodlate
> pare. Tai: **blocklist din e 2 bar, auth din e 1 bar** (ba soptahe ekbar)।
> Ei ek sidhanto e din e ~3 ghonta kaj bache.

### DNS query (asol constraint ekhane)

Ekta domain e: **55 ta IP zone × (max 2 IP) + 14 ta domain zone**. Sob trusted
hole 124 query, bastobe trusted count onujayi kom.

Nijer resolver + DQS key diye jodi ~50 ta zone trusted hoy (~40 IP + ~10 domain):

```
  IP zone   :  10,000 domain × 2 IP × 40 zone  =  800,000 query
  domain    :  10,000 domain ×        10 zone  =  100,000 query
  --------------------------------------------------------------
  ek sweep  :  900,000     |     din e (2 sweep)  :  1,800,000
```

**Eta chalano jabe na.** Kono DNSBL ei volume soibe na, DQS quota-o shesh।

### IP dedup. Ei ekta jinis-i eta ke sombhob kore

**IP-zone er uttor domain er upor nirbhor kore na, IP er upor kore.** 10,000
domain er moddhe onek gulo eki hosting, eki CDN, eki mail server e. Bastobe
10,000 domain e prai 2,000 theke 3,000 unique IP pawa jay.

Sweep er bhitore ekta IP cache rakhle:

```
  IP zone   :  3,000 unique IP × 40 zone       =  120,000 query   (800,000 er bodole)
  domain    :  10,000 domain  × 10 zone        =  100,000 query
  --------------------------------------------------------------
  ek sweep  :  220,000     |     din e         :   440,000
```

**~75% query kome jay.** Ei cache ta sweep-scoped (sweep sesh hole feka jay),
tai basi data er risk nai. Domain zone (RHSBL/URIBL) domain prati-i cholbe,
karon oigulo domain er upor uttor dey.

Ei jonno-i architecture e IP cache ta ekta **alada layer**, worker er bhitore
lukono kono optimization na.

### Ki ki obosshoi lagbe

Ei scale e egulo optional na:

| Jinis | Keno |
|---|---|
| **Nijer recursive resolver** (Unbound), same server e | Public resolver (1.1.1.1 / 8.8.8.8) ei volume e tomake block korbe, ar Spamhaus emniteo public resolver ke uttor dey na |
| **Spamhaus DQS key** | Chara Spamhaus `silent` thake, mane 2 ta `critical` list-i skip hoy, mane `blacklisted` verdict kokhono asbe na |
| **DQS tier check** | Tomar tier er dainik query limit hisheb kore melao (upore hisheb ta ache)। Free tier ei volume e possibly kombe na, paid tier lagte pare |
| **Dedicated / colo VPS** (Hetzner, OVH) | AWS/GCP/Azure er IP range onek DNSBL block kore rakhe |
| **Postgres** | Ekhon optional, ei workflow e **obosshoi** |

---

## 8. Database schema (notun ar bodlano)

Purono 5 ta table (`users`, `domains`, `checks`, `monitors`, `alerts`) theke
`monitors` ar `alerts` ei workflow e proyojon nai. Tader jayga ney sweep +
incident + notification model.

### Notun: tenant kathamo

```sql
-- Client / company. 10,000 domain egulor moddhe bhag hobe.
CREATE TABLE clients (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name        TEXT        NOT NULL,
  active      BOOLEAN     NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE user_role AS ENUM ('super_admin', 'admin', 'account_manager', 'client_user');
CREATE TYPE delivery_mode AS ENUM ('immediate', 'digest', 'critical_only', 'off');
CREATE TYPE notify_channel AS ENUM ('email', 'sms', 'whatsapp', 'slack', 'webhook');

ALTER TABLE users ADD COLUMN role      user_role      NOT NULL DEFAULT 'client_user';
ALTER TABLE users ADD COLUMN client_id BIGINT REFERENCES clients(id) ON DELETE CASCADE;
ALTER TABLE users ADD COLUMN mode      delivery_mode  NOT NULL DEFAULT 'immediate';
ALTER TABLE users ADD COLUMN channel   notify_channel NOT NULL DEFAULT 'email';

-- Kon account manager kon client er under e. Ek manager onek client, ek client
-- onek manager, duitai sombhob.
CREATE TABLE client_managers (
  client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id   BIGINT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  PRIMARY KEY (client_id, user_id)
);

-- Domain ekhon ekta client er.
ALTER TABLE domains ADD COLUMN client_id  BIGINT REFERENCES clients(id) ON DELETE CASCADE;
ALTER TABLE domains ADD COLUMN active     BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE domains ADD COLUMN baselined  BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX domains_client_idx ON domains (client_id) WHERE active;
```

### Notun: sweep ar queue

```sql
CREATE TYPE sweep_status AS ENUM ('running', 'done', 'aborted', 'held');

CREATE TABLE sweeps (
  id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  status         sweep_status NOT NULL DEFAULT 'running',
  baseline       BOOLEAN      NOT NULL DEFAULT false,
  trusted_zones  SMALLINT,             -- Gate 1 er hisheb
  total_domains  INTEGER      NOT NULL DEFAULT 0,
  done_domains   INTEGER      NOT NULL DEFAULT 0,
  new_listings   INTEGER      NOT NULL DEFAULT 0,
  abort_reason   TEXT,
  started_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  finished_at    TIMESTAMPTZ
);

CREATE TYPE job_state AS ENUM ('pending', 'running', 'done', 'failed');

CREATE TABLE sweep_jobs (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sweep_id   BIGINT    NOT NULL REFERENCES sweeps(id)  ON DELETE CASCADE,
  domain_id  BIGINT    NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  state      job_state NOT NULL DEFAULT 'pending',
  attempts   SMALLINT  NOT NULL DEFAULT 0,
  locked_at  TIMESTAMPTZ,
  error      TEXT,
  UNIQUE (sweep_id, domain_id)
);

-- Worker er claim query ei index ta use kore.
CREATE INDEX sweep_jobs_claim_idx ON sweep_jobs (sweep_id, state) WHERE state = 'pending';
```

Worker er claim (ekta job duijon niye felbe na):

```sql
UPDATE sweep_jobs SET state = 'running', locked_at = now(), attempts = attempts + 1
WHERE id IN (
  SELECT id FROM sweep_jobs
  WHERE sweep_id = $1 AND state = 'pending'
  ORDER BY id
  FOR UPDATE SKIP LOCKED
  LIMIT $2
)
RETURNING id, domain_id;
```

### Notun: state ar incident

```sql
-- Protita (domain, zone) er ekhon er obostha. Ei table ta-i "age ki chilo".
-- 10,000 domain × ~50 zone = ~500,000 row. Postgres er jonno kichui na.
CREATE TABLE domain_zone_state (
  domain_id    BIGINT      NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  zone         TEXT        NOT NULL,
  listed       BOOLEAN     NOT NULL,
  subject      TEXT,                    -- kon IP ba domain listed
  since        TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  unknown_since TIMESTAMPTZ,            -- kobe theke uttor pacchi na
  PRIMARY KEY (domain_id, zone)
);

CREATE TYPE incident_status AS ENUM ('open', 'closed', 'noisy');

CREATE TABLE incidents (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  domain_id   BIGINT          NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  client_id   BIGINT          NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  zone        TEXT            NOT NULL,
  subject     TEXT,
  severity    TEXT            NOT NULL,  -- zones.js theke
  status      incident_status NOT NULL DEFAULT 'open',
  flap_count  SMALLINT        NOT NULL DEFAULT 0,
  opened_at   TIMESTAMPTZ     NOT NULL DEFAULT now(),
  closed_at   TIMESTAMPTZ,
  opened_by_sweep BIGINT REFERENCES sweeps(id)
);

-- Ekta (domain, zone) er ekta-i open incident thakte parbe.
CREATE UNIQUE INDEX incidents_one_open_idx ON incidents (domain_id, zone)
  WHERE status = 'open';
CREATE INDEX incidents_client_open_idx ON incidents (client_id, opened_at DESC)
  WHERE status = 'open';
```

### Notun: notification outbox

```sql
CREATE TYPE notif_status   AS ENUM ('pending', 'held', 'sent', 'failed', 'cancelled');
CREATE TYPE delivery_state AS ENUM ('pending', 'sent', 'failed');

CREATE TABLE notifications (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  client_id       BIGINT       NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  sweep_id        BIGINT       NOT NULL REFERENCES sweeps(id)  ON DELETE CASCADE,
  kind            TEXT         NOT NULL,   -- 'new_listing' | 'cleared' | 'digest'
  incident_count  SMALLINT     NOT NULL,
  payload         JSONB        NOT NULL,   -- render korar jonno sob data
  status          notif_status NOT NULL DEFAULT 'pending',
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  -- Eki sweep e eki client ke duibar message jabe na.
  UNIQUE (sweep_id, client_id, kind)
);

CREATE TABLE notification_deliveries (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  notification_id BIGINT         NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  user_id         BIGINT         REFERENCES users(id) ON DELETE SET NULL,
  address         TEXT           NOT NULL,     -- email / phone / webhook url
  channel         notify_channel NOT NULL,
  role_at_send    user_role      NOT NULL,     -- itihas: tokhon ke ki chilo
  is_cc           BOOLEAN        NOT NULL DEFAULT false,
  state           delivery_state NOT NULL DEFAULT 'pending',
  attempts        SMALLINT       NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ    NOT NULL DEFAULT now(),
  error           TEXT,
  sent_at         TIMESTAMPTZ
);

-- Delivery worker er kaj: ki ki ekhon pathate hobe.
CREATE INDEX deliveries_due_idx ON notification_deliveries (next_attempt_at)
  WHERE state = 'pending';
```

`checks` table ta jemon ache temon-i thakbe (history + JSONB), sudhu ekta
`sweep_id` column jog hobe jate "ei sweep e ki ki holo" ek query te pawa jay.

---

## 9. Code map. Ki notun, ki bodlabe, ki hat-i porbe na

### Notun (ei workflow er jonno banate hobe)

| File | Kaj |
|---|---|
| `src/jobs/scheduler.js` | Din e 2 bar sweep toiri, calibration, Gate 1, queue bhorti |
| `src/jobs/worker.js` | Job claim (SKIP LOCKED), check chalano, result save, state engine call |
| `src/jobs/delivery-worker.js` | Outbox theke pending delivery pathano, retry, backoff |
| `src/lib/state.js` | Age vs ekhon milano, incident open/close, confirm step, flap protection |
| `src/lib/ipcache.js` | Sweep-scoped IP to zone-result cache (§7 er 75% sasroy) |
| `src/lib/gate.js` | Gate 1 ar Gate 2 er niyom, ek jaygay |
| `src/notify/recipients.js` | Client theke To/CC list ber kora (role + client_managers) |
| `src/notify/render.js` | Message er subject ar body banano |
| `src/notify/channels/email.js` | Email adapter (prothom channel) |
| `src/db/repositories/clients.js` | clients, client_managers |
| `src/db/repositories/sweeps.js` | sweeps, sweep_jobs |
| `src/db/repositories/incidents.js` | domain_zone_state, incidents |
| `src/db/repositories/notifications.js` | notifications, notification_deliveries |
| `src/db/migrations/002_monitoring.sql` | Upor er sob DDL |

### Bodlabe

| File | Ki bodlabe |
|---|---|
| `src/lib/check.js` | `opts.ipCache` neoa (query korar age cache dekhbe) ar `opts.calibration` sweep theke pawa (protita domain e abar calibrate korbe na) |
| `src/server.js` | Notun read-only route: sweep status, incident list, held notification release, client/domain CRUD |
| `public/index.html` | Notun tab: **Monitoring** (sweep history, open incident, client onujayi view, held notification approve) |
| `src/db/index.js` | Notun repository gulo jog |

### Ekdom hat porbe na (ei gulo-i core, ar egulo thik ache)

```
  src/lib/zones.js       blocklist catalog, return code semantics
  src/lib/resolve.js     DNS query, listed/clean/unknown niyom
  src/lib/calibrate.js   kon list trust kora jay
  src/lib/score.js       weighted score ar verdict
  src/lib/normalize.js   input -> registrable domain
  src/lib/auth.js        SPF / DKIM / DMARC / MX / PTR
  src/lib/recommend.js   findings -> ki korte hobe
  src/lib/delist.js      removal readiness, prefill, watch
```

Purono `monitors` ar `alerts` table (ar tader repository) ei model e `sweeps` +
`incidents` diye replace hocche. Migration e drop na kore rekhe deoa jay, kintu
notun kono code tader use korbe na.

---

## 10. Deploy shape

```
  ┌─────────────────────────────────────────────────────────┐
  │  EK TA SERVER (VPS, dedicated IP)                        │
  │                                                          │
  │   unbound          127.0.0.1:53   nijer recursive resolver│
  │   postgres         5432                                   │
  │   app: web         :3000          UI + API (1 process)    │
  │   app: scheduler                  cron, 06:00 ar 18:00    │
  │   app: worker × N                 sweep job kore          │
  │   app: delivery                   outbox pathay           │
  └─────────────────────────────────────────────────────────┘
```

Sob ekta process-e chalano jabe (chhoto setup), abar alada process-o kora jay.
`sweep_jobs` Postgres e thakay **worker koyta cholche seta gurutto purno na**:
duita server e 4 ta worker cholleo `SKIP LOCKED` er jonno ekta domain duibar
check hobe na. Scale korte hole sudhu worker baraw.

`DBC_BULK_CONCURRENCY` er bodle worker count diye niyontron hobe, ar sathe
`DBC_QUERY_CONCURRENCY` (protita domain er bhitore koyta DNS query ek shathe)।

---

## 11. Kon order e banate hobe

Protita step er sheshe kichu ekta kaj kore, tai majh khane thamleo khoti nai.

| Phase | Ki | Sesh e ki paba |
|---|---|---|
| **1** | Migration 002: clients, roles, sweeps, jobs, state, incidents, notifications | Schema ready |
| **2** | `scheduler.js` + `worker.js` + Gate 1 | 10,000 domain automatic check hocche, DB te result jomche. Alert nai |
| **3** | `ipcache.js` | Query 75% kome gelo, sweep dut hoye gelo |
| **4** | `state.js` (transition + confirm + flap) + baseline mode | Incident toiri hocche, kintu message jay na |
| **5** | `recipients.js` + `render.js` + email channel + outbox | **Puro workflow chalu.** Client message pacche, CC hocche |
| **6** | Gate 2 + held notification approve UI | Mittha mass-alert theke nirapod |
| **7** | Monitoring tab (sweep history, incident list, client view) | Manush chokh diye dekhte parche |

Phase 5 er sheshe tomar bola workflow ta puro kaj kore. 6 ar 7 na thakle-o
chole, kintu 6 ta na thakle ekdin ekta bhul calibration e sob client ke mittha
message chole jete pare.

---

## 12. Sonkha, ek jaygay

| | |
|---|---|
| Domain | 10,000+ |
| Sweep | din e 2 bar |
| Ek sweep er somoy | ~71 minute (blocklist only, concurrency 20) |
| Din e engine cholbe | ~2.4 ghonta |
| Blocklist catalog | 69 (55 IP zone, 14 domain zone) |
| `critical` zone | 2 (Spamhaus ZEN, DBL). Egulo-i `blacklisted` verdict dey |
| DNS query, IP cache chara | ~1,800,000 / din |
| DNS query, IP cache soho | ~440,000 / din |
| `domain_zone_state` row | ~500,000 |
| Notification, kharap din e | ~40 (client prati ekta, domain prati na) |
