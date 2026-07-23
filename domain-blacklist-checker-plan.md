# Domain Blacklist Checker — Full Plan

> Ekta domain diye check kora jabe se kono spam/malware blacklist e ache kina, ar thakle kivabe delist korte hobe.

---

## 1. Scope thik koro (ki check korbe)

Ekta domain input nile 3 ta level e check hobe:

| Level | Ki check hoy | Kar jonno dorkar |
|---|---|---|
| **IP-based DNSBL** | Domain er A record → protita IP | Email deliverability |
| **Domain-based DNSBL** | Domain name direct | Spam/phishing domain |
| **URL reputation API** | Malware, phishing feed | Security/safety |

**Bonus (upsell hishebe valo):** SPF, DKIM, DMARC, MX, rDNS/PTR check — ek shathe ekta "email health score" dao.

---

## 2. Data sources

### DNSBL zones (free, DNS query diye)

| Zone | Type | Note |
|---|---|---|
| `zen.spamhaus.org` | IP | Shobcheye important |
| `dbl.spamhaus.org` | Domain | Shobcheye important |
| `b.barracudacentral.org` | IP | Registration lage |
| `bl.spamcop.net` | IP | — |
| `dnsbl.sorbs.net` | IP | Informational |
| `psbl.surriel.com` | IP | — |
| `multi.surbl.org` | Domain/URI | — |
| `multi.uribl.com` | Domain/URI | — |

Total **~50–80 ta zone** list koro, kintu weight alada rakho — Spamhaus listing = critical, SORBS = informational.

### API-based

- **Google Safe Browsing API** — free, quota valo
- **URLhaus + abuse.ch feeds** — free, download kore local e rakha jay
- **VirusTotal** — free tier: 4 req/min → cache mandatory
- **PhishTank / OpenPhish** — phishing feed
- **AbuseIPDB** — IP reputation

---

## 3. Core logic

```
input → normalize (lowercase, strip www/protocol, punycode,
                   public-suffix diye registrable domain ber koro)
     → DNS resolve (A, AAAA, MX)
     → parallel fan-out:
          IP list  × IP zones     (reversed-octet query)
          domain   × domain zones (direct query)
          domain   × APIs
     → aggregate + weighted score (0-100)
     → cache (Redis, TTL 30 min) + save to DB
```

DNSBL lookup basically ekta A-record query. `1.2.3.4` er jonno `4.3.2.1.zen.spamhaus.org` query koro — reply `127.0.0.x` ashle **listed**, NXDOMAIN ashle **clean**. Return code diye bola jay kon sub-list e ache.

```js
import { Resolver } from 'node:dns/promises';

const resolver = new Resolver({ timeout: 3000, tries: 1 });
resolver.setServers(['127.0.0.1']); // nijer recursive resolver

const rev = ip => ip.split('.').reverse().join('.');

async function checkIp(ip, zone) {
  try {
    const codes = await resolver.resolve4(`${rev(ip)}.${zone}`);
    return { zone, listed: true, codes };
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA')
      return { zone, listed: false };
    return { zone, listed: null, error: e.code }; // timeout = unknown, "clean" na
  }
}
```

`Promise.allSettled` diye shob zone parallel e maro — per-query timeout 3s, overall 8s cap.

---

## 4. Tech stack (recommendation)

| Layer | Choice | Keno |
|---|---|---|
| Backend | Node.js + Fastify | DNS I/O heavy, event loop e valo fit |
| Alt backend | Python + FastAPI + `dnspython` + asyncio | Same kaj, Python prefer korle |
| Frontend | Next.js + Tailwind | Result table + severity badge |
| Cache | Redis | Domain-wise result, 15–30 min TTL |
| Queue | BullMQ | Bulk check ar scheduled monitoring |
| DB | PostgreSQL | users, checks, monitors, alerts |
| Resolver | **nijer Unbound container** | Ei point miss korle project fail korbe (niche dekho) |

---

## 5. Critical gotchas — ei gula na jene shuru korle atke jabe

1. **Spamhaus public resolver block kore.** Google DNS (8.8.8.8) ba Cloudflare (1.1.1.1) theke query korle shob domain "listed" dekhabe (`127.255.255.254` return kore). **Solution:** nijer Unbound recursive resolver run koro, othoba Spamhaus DQS free key nao.
2. **Cloud IP e problem.** AWS/GCP/Azure er shared IP range theke onek DNSBL query block kore. Hetzner/OVH/dedicated VPS beshi safe.
3. **Free usage limit.** Beshirbhag DNSBL free use ~100k query/day porjonto, tar upore commercial license lage. Tai caching optional na — **mandatory**.
4. **Timeout ≠ clean.** Error hole "not listed" dekhano bhul; alada **"unknown"** state rakho.
5. **Rate limit nijer API te o rakho**, noyto keu abuse kore tomar IP block koraye debe.
6. **Delisting info dekhao** — protita listing er shathe kon list, keno, ar delist link. Eitai actual value.

---

## 6. DB schema (minimal)

```sql
users(id, email, plan, api_key)
domains(id, name, first_seen)
checks(id, domain_id, user_id, score, raw_result jsonb, created_at)
monitors(id, user_id, domain_id, frequency, notify_email, active)
alerts(id, monitor_id, zone, status_change, created_at)
```

---

## 7. Roadmap

| Phase | Kaj | Time |
|---|---|---|
| **MVP** | 20–30 DNSBL zone, single domain check, ek page UI, no auth | 1 week |
| **v1** | Redis cache, own resolver, Safe Browsing + URLhaus, SPF/DKIM/DMARC, delist guide | 2 weeks |
| **v2** | Auth, bulk upload (CSV), REST API + key, history | 2 weeks |
| **v3** | Scheduled monitoring + email/Slack alert, PDF report, white-label | 3 weeks |

---

## 8. Monetization

| Plan | Price | Ki thakbe |
|---|---|---|
| Free | $0 | 5 check/day |
| Pro | $9/mo | Unlimited check + 10 domain monitoring |
| Agency | $49/mo | API access, 100 domain, white-label report |

**Monitoring + alert** tai main paid feature — one-time check to shobai free te dey.
