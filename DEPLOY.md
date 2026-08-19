# Deploying to production (example: blacklist.deliverlymail.com)

The app is a single Node process serving both the API and the UI. Production
needs four things around it: DNS, a process manager, HTTPS in front, and the
right .env. Nothing else.

## 1. DNS

Point the hostname at your server:

```
blacklist.deliverlymail.com.   A     <your server IPv4>
```

## 2. Server prerequisites

- Ubuntu/Debian VPS (1 GB RAM is plenty)
- Node.js 22+ (`node -v`)
- The project folder, e.g. `/opt/blacklist-checker`, then:

```
cd /opt/blacklist-checker
npm ci --omit=dev
```

## 3. .env for production

Create `/opt/blacklist-checker/.env`:

```
PORT=3000

# CHANGE THESE. The defaults are publicly known from the source code.
DBC_ADMIN_USER=admin
DBC_ADMIN_PASS=<a long random password>
DBC_USER_USER=user
DBC_USER_PASS=<a different long random password>

# Behind nginx/Caddy with HTTPS:
DBC_COOKIE_SECURE=true
DBC_TRUST_PROXY=true

# Database (Supabase session pooler, port 5432):
DATABASE_URL=postgresql://postgres.<project-ref>:<PASSWORD>@aws-0-<region>.pooler.supabase.com:5432/postgres
DATABASE_SSL=true

# DNS resolvers used for blocklist queries (see the note below):
DBC_RESOLVERS=127.0.0.1
```

The server migrates the database schema itself at startup; there is no
separate migrate step to remember.

### The resolver note (this affects result accuracy)

Several blocklists (SURBL, Spamhaus, URIBL) refuse or throttle queries that
arrive from big public resolvers like 8.8.8.8 or 1.1.1.1. On a production
box, run a small local recursive resolver and point the app at it:

```
apt install unbound
systemctl enable --now unbound
# then in .env: DBC_RESOLVERS=127.0.0.1
```

With a local resolver the queries come from your own IP, which these lists
accept, and calibration marks more zones as trustworthy.

## 4. Run it as a service

`/etc/systemd/system/blacklist-checker.service`:

```
[Unit]
Description=Domain Blacklist Checker
After=network-online.target

[Service]
WorkingDirectory=/opt/blacklist-checker
ExecStart=/usr/bin/node src/server.js
Restart=always
RestartSec=3
User=www-data
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
systemctl enable --now blacklist-checker
journalctl -u blacklist-checker -f   # watch the logs
```

## 5. HTTPS in front

Easiest is Caddy (automatic certificates):

```
apt install caddy
```

`/etc/caddy/Caddyfile`:

```
blacklist.deliverlymail.com {
    reverse_proxy 127.0.0.1:3000
}
```

`systemctl reload caddy` and HTTPS just works.

nginx + certbot works the same way; proxy to 127.0.0.1:3000 and make sure
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` is set, since
DBC_TRUST_PROXY=true reads it for rate limiting and the Visitors page.

## 6. After it is up

- `https://blacklist.deliverlymail.com/api/health` must show `"db":"ok"`.
  `"db":"error"` names the reason (bad DATABASE_URL, network, TLS).
- Log in with the NEW credentials from .env; the defaults must not work.
- Run one check and confirm a row lands in the `checks` table.
- Share links (`/r/<id>`) are relative, so they work on the new domain with
  no extra configuration.

## Updating a running deployment

```
cd /opt/blacklist-checker
# replace the files with the new version (keep your .env and any brand art)
npm ci --omit=dev
systemctl restart blacklist-checker
```

The startup migration applies any new schema automatically.
