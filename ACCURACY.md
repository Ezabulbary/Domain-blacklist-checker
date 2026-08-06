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
nslookup 2.0.0.127.dnsbl.spfbl.net        → 127.0.0.2    = list er test entry, sotti listed
nslookup 1.0.0.127.dnsbl.spfbl.net        → Non-existent = list ta mittha bole na
```
Duita-i mille bujhbe list ta **discriminate korche**. Mane tar answer
bishwasjoggo।


---

## 6. Delisting: ki automate hoy, ki hoy na

**Puro automatic delist sombhob na.** Karon:

| Badha | Bastobota |
|---|---|
| CAPTCHA | SURBL, Barracuda, SPFBL, UCEPROTECT er form e CAPTCHA |
| Email confirmation | Onek list `postmaster@` / `abuse@` te confirm pathay |
| Manual review | Spamhaus SBL manush dekhe |
| Terms of service | Beshirbhag list automated submission **nishedh** kore |
| Taka | UCEPROTECT express removal paid |

Bot diye form submit korle **amader server er IP-i ban** hobe, ar oi list theke
sob client er result nosto hobe. Tai amra ta kori na.

**Ja automate kora hoyeche (Start removal button):**

1. **Readiness check.** Live DNS diye dekhe tumi oi list er short purno korecho
   kina: PTR ache kina, PTR ulta kore same IP e ase kina (FCrDNS), domain e MX
   ache kina (confirmation mail pabe kina), SPF ar DMARC ache kina. Na thakle
   **FIX** mark kore dekhay. Ei gulo na thakle removal request **reject** hoto.
2. **Already cleared?** Button e click korar somoy list ke abar jiggesh kore.
   Age theke clear hoye thakle bole dey, khali khali form bhorte hoy na.
3. **Auto-clearing list chinte pare.** SpamCop, UCEPROTECT L1, Backscatterer,
   Truncate, blocklist.de, PSBL, egulo nije-i chole jay. Tokhon "form nai, sudhu
   karon thamao ar opekkha koro" bole.
4. **Prefilled form.** Removal page ta IP/domain already bhora obosthay khole.
5. **Watch until cleared.** Request pathanor por prottek minute e list ke abar
   query kore, jokhon entry chole jabe tokhon bole dey.

Mane: **manush ekbar form ta submit korbe, baki sob tool kore dey.**

---

## 7. Return code er mane. "Listed" ar "policy flag" ek jinis na

Ekta zone e sob 127.0.0.x code **"tumi spammer"** mane na. Kichu code shudhu
**address ta somporke ekta policy kotha** bole. Duitake ek kore dhorle mittha
LISTED toiri hoy.

**Dhora pora bug (fix kora hoyeche):** `dnsbl.spfbl.net`

| Code | Mane | Listing? |
|---|---|---|
| `127.0.0.2` | confirmed spam source | ✅ haa |
| `127.0.0.3` | suspected spam, ba RFC 5321 mene chole na | ✅ haa |
| `127.0.0.4` | ei address e kono mail service nai (NAT / residential) | ❌ **na** |
| `127.0.0.5` | ei IP range er abuse contact bishwasjoggo na | ❌ **na** |

Amra domain er **A record** check kori, ar A record mane **web server**, mail
server na. Tai `127.0.0.4` prochur domain er jonno ase. Proman, 30 ta boro
bhalo domain diye test:

```
age  : 11/30 "listed"   (9 tai shudhu SPFBL 127.0.0.4)
ekhon:  6/30 "listed"   (SPFBL er policy flag ar listing hishebe gone hoy na)
```

SPFBL nije-o bole ei zone diye SMTP e mail **reject kora jabe na**, shudhu
scoring e use korte hobe. Tai eta listing na. Ekhon row ta **clean** dekhay, ar
code er mane pashe lekha thake, jate tothyo hariye na jay.

**Kivabe fix hoyeche:** zone catalog e `listedCodes` dile shudhu oi code gulo
listing hishebe gone hoy (`src/lib/zones.js`). Hostkarma-o eki vabe kaj kore
(tar `127.0.0.1` = whitelist, listing na).

### ZapBL RHSBL somporke ekta kotha
`rhsbl.zapbl.net` **sotti** microsoft.com, cloudflare.com, github.com,
netflix.com, nytimes.com ke listed bole. Eta mittha na, list ta discriminate
kore (google.com, apple.com, iana.org → clean, zone er serial-o taja). Mane
ZapBL sotti-i aggressive. Tai amra row ta **dekhai** (lukai na), kintu tar
weight 5 (low) rakha, jate score e prabhab kom pore. 60 ta boro domain e tar
hit rate 12%.

### Nijei protita LISTED verify korar niyom
1. Row er code ta dekho (`127.0.0.x`).
2. Oi code ta oi list er **spam** code kina, na **policy** code, seta list er
   documentation e milao. Row e mane ta already lekha thake.
3. Control probe: `nslookup 1.0.0.127.<zone>` → **Non-existent** hote hobe.
   Na hole list ta shobaike listed bole, ar amader calibration take baad dey.
