# Onno keu tomar tool try korte chaile — 3 ta way

Tomar tool `http://localhost:3000` e cholche. "localhost" mane sudhu tomar PC.
Onno keu (onno location theke) try korte hole ekta **public/shareable address**
lagbe. Sohoj theke sthayi — 3 ta option:

---

## Option 1 — Instant public link (tunnel)  ⭐ shobcheye shohoj

Tomar PC te tool cholte thakbe, ekta command ekta **public HTTPS link** diye debe
ja tumi kauke pathate paro. (Tomar PC on thakte hobe + `npm start` cholte hobe.)

### 1A. Cloudflare Tunnel (free, signup lage na, HTTPS)
1. `cloudflared` install koro: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
   (Windows e `.msi`, ba `winget install --id Cloudflare.cloudflared`)
2. Ek terminal e tool chalao: `npm start`
3. Arek terminal e:
   ```
   cloudflared tunnel --url http://localhost:3000
   ```
4. Ekta link dekhabe jemon `https://random-words.trycloudflare.com` — **eita
   kauke pathao**, tara browser e khule try korte parbe. Bondho korte `Ctrl+C`.

### 1B. localtunnel (npm, install lage na)
```
npx localtunnel --port 3000
```
Ekta `https://xxxx.loca.lt` link debe. (Prothome ekta "click to continue" page
dekhate pare — normal.)

> **Note:** Tunnel chola obostay tomar PC on ar server chalu thakte hobe. PC bondho
> = link kaj korbe na. Sthayi hole Option 3 dekho.

---

## Option 2 — Ekই WiFi/network e keu thakle (LAN)

Onno keu jodi **tomar-i WiFi/office network** e thake, public link lage na:
1. Tomar local IP ber koro:
   - Windows: `ipconfig` → "IPv4 Address" (jemon `192.168.1.25`)
   - Mac/Linux: `ifconfig` ba `ip addr`
2. `npm start` chalao.
3. Oi jon browser e likhbe: `http://192.168.1.25:3000` (tomar IP diye)।
4. Kaj na korle: Windows Firewall e Node ke allow koro (prothombar prompt ashe)।

---

## Option 3 — Always online (deploy — sthayi)

PC bondho thakleo 24/7 cholbe emon chaile ekta **host/server** e deploy koro.

**Sohoj platform (Node app support kore):**
- **Render** / **Railway** / **Fly.io** — GitHub repo connect korle auto build+deploy.
- Ekta **VPS** (Hetzner / DigitalOcean / Contabo) — beshi control.

**Ei tool er jonno bishesh note:**
- Deploy koro, kintu **accurate blacklist result** er jonno `DBC_RESOLVERS` ekta
  valo resolver e set koro (cloud er default IP kichu DNSBL block kore)। Best:
  **VPS + nijer Unbound resolver + `DBC_TRUST_KEYED=true`**.
- Project e ekta **`Dockerfile`** ache — jekono Docker-supported host e deploy kora
  jabe:
  ```
  docker build -t blacklist-checker .
  docker run -p 3000:3000 -e DBC_RESOLVERS=1.1.1.1 blacklist-checker
  ```
- Ba direct Node diye (VPS e):
  ```
  npm install
  PORT=3000 npm start
  ```
  Tarpor ekta domain + reverse proxy (nginx/Caddy) diye HTTPS dao.

---

## Kon ta beche nebo?

| Dorkar | Option |
|---|---|
| Ekjon-ke ekbar dekhabo, ekhoni | **Option 1** (tunnel) |
| Same office/WiFi er keu | **Option 2** (LAN) |
| Shobar jonno, sob somoy online | **Option 3** (deploy) |

Setup e atke gele bolo — step-by-step kore debo.
