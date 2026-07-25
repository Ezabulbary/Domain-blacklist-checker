# Accuracy. Keno onno site ar amader result alada chilo (research + fix)

**Somossa:** ekta domain (`reachoutly.com`) mxtoolbox e "Listed 0, 0 timeout"
dekhacchilo, kintu amader site e **5 LISTED + 7 TIMEOUT** dekhacchilo.

Ei document e: karon ki, kivabe proman korlam, ar ki fix korlam.

---

## 1. Research: ekta DNSBL 3 vabe mittha bolte pare

DNSBL er ekta standard contract ache:

| Query | Ki asha kori |
|---|---|
| `127.0.0.2` | **LISTED** (protita list er permanent test entry) |
| `127.0.0.1` | **NEVER listed** (universal control) |

Ei duita diye probe korle 3 rokom "mittha" dhora pore:

### (a) ALWAYS-POSITIVE. Mittha LISTED
List ta **protita query te "listed"** bole. Subscription-only list gulo
non-subscriber ke eta kore.

**Proof (nijei chalate paro):**
```
nslookup 8.8.8.8.sip.invaluement.com     → 127.0.0.2
```
Google er 8.8.8.8-o "listed"?! Mane oi list **shobaike** listed bole.

→ **Ei tinta list amader 5 ta false LISTED banachhilo:**
`ivmSIP`, `ivmSIP24`, `ivmURI` (invaluement. Paid subscription lage)।

### (b) SILENT. Mittha CLEAN (shobcheye bipojjonok)
List ta amader query **chup kore ignore kore**, sob kichute NXDOMAIN dey.
Dekhte "clean" lage, kintu asole **kono uttor-i pai ni**.

**Proof:**
```
nslookup 2.0.0.127.zen.spamhaus.org      → Non-existent domain
nslookup dbltest.com.dbl.spamhaus.org    → Non-existent domain
```
Spamhaus er **nijer test entry-o "listed na"**. Mane amader ignore korche
(public resolver theke query bole)। Tai Spamhaus er "clean" amader jonno
**ortho-hin**।

### (c) BLOCKED. Refusal code
```
nslookup test.uribl.com.multi.uribl.com  → 127.0.0.1   (URIBL: "Query Refused")
Sender Score                              → 127.255.255.255 (not authorized)
```

---

## 2. Keno mxtoolbox parche, amra parchi na?

mxtoolbox er **authorized/paid access** ache (Spamhaus DQS, invaluement
subscription, nijer resolver)। Tai:
- Spamhaus tader ke **sotti uttor** dey → tara confidently "0 listed" bole।
- invaluement tader ke **sotti uttor** dey → tara false positive paay na।

Amra public resolver theke query korle oi list gulo **hoy mittha bole, noy chup
kore thake**। Tader answer ke "clean" ba "listed" dhora **bhul**।

---

## 3. Fix: runtime calibration (`src/lib/calibrate.js`)

Ekhon app **nije theke protita list ke live test kore**. Test point + control
probe kore. Ar shudhu je list gulo **prokrito pokkhe thik uttor dey** segulo
diye score kore.

| Verdict | Mane | Score e dhora hoy? |
|---|---|---|
| `verified` | test entry listed + control clean | ✅ haa (full trust) |
| `answering` | alive, control clean (test entry nai) | ✅ haa |
| `always-positive` | control-o "listed" | ❌ **na** (false positive banabe) |
| `silent` | nijer test entry-o "listed na" | ❌ **na** (false clean banabe) |
| `blocked` | refusal code / SERVFAIL | ❌ na |
| `dead` | zone resolve-i kore na | ❌ na |

Baki gulo **SKIPPED** dekhabe, **karon soho** ("needs a subscription",
"ignores our queries", …)। Mittha number er cheye **sotti "janina"** bhalo.

**Chalao:**
```
npm run calibrate          # report dekhabe, kon list trust kora jay
```
Result `.calibration.json` e cache hoy (12 ghonta), ar `/api/calibration`
endpoint diye-o dekha jay।

### Ei server theke ekhon (public resolver diye):
```
40/69 blocklists trusted
verified: 30 · answering: 10 · silent: 18 · blocked: 5 · always-positive: 3 · dead: 3
```

### Result (age vs ekhon), `reachoutly.com`
| | Age | Ekhon | mxtoolbox |
|---|---|---|---|
| Listed | **5** (sob false) | **0** ✅ | 0 |
| Timeout | 7 | **0** ✅ | 0 |

---

## 4. Aro beshi list trust korte chaile (coverage barano)

Ekhon 40 ta trusted. Baki gulo unlock korar upay, **effect onujayi sajano**:

### ⭐ 1. Spamhaus DQS key (free). Shobcheye boro labh, shobcheye sohoj
Spamhaus-i shobcheye important list. Key thakle **jekono network theke** kaj kore, nijer resolver-o lage na (PaaS/Render/Railway e ei tai best)।

1. Free key nao: https://www.spamhaus.com/free-trial/ (26-character key)
2. Env e dao:
   ```
   DBC_DQS_KEY=your26characterkeyfromspamhaus
   ```
3. `npm run calibrate` → **Spamhaus ZEN + DBL `verified`** hoye jabe.

App nije-i DQS zone banay (`<key>.zen.dq.spamhaus.net`)। **Key ta secret thake, API/UI te kokhono dekha jay na** (test kora ache)। Key bhul hole calibration
`blocked, DQS key rejected` dekhabe, chup kore mittha result debe **na**।

### 2. Nijer recursive resolver (Unbound), VPS thakle
Public resolver er block (URIBL, kichu list) ese jabe na:
```
DBC_RESOLVERS=127.0.0.1
```

### 3. Abusix free trial key / invaluement subscription
Egulo paid/registration. Na hoy `skipped` thakbe (kono khoti nai)।

Tarpor abar: `npm run calibrate`. Trusted count baré jabe.

> **PaaS (Render/Railway/Fly) e deploy korle:** `DBC_DQS_KEY` + `DBC_TRUST_PROXY=true`
> dao. Platform er resolver diye baki list gulo emniteo kaj kore.

> Note: cloud VPS (AWS/GCP/Azure) er IP theke onek DNSBL block kore। Hetzner/
> OVH/dedicated VPS beshi valo।

---

## 5. Nijei verify koro

Protita LISTED/CLEAN ekta real DNS answer, `nslookup` diye milao:
```
nslookup 96.8.26.104.dnsbl.spfbl.net      → 127.0.0.4    = sotti listed
nslookup 1.0.0.127.dnsbl.spfbl.net        → Non-existent = list ta mittha bole na
```
Duita-i mille bujhbe list ta **discriminate korche**. Mane tar answer
bishwasjoggo।
