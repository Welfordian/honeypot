# Deployment Runbook

## Cloudflare

Create resources:

```sh
npx wrangler r2 bucket create honeypot-events
npx wrangler d1 create honeypot-analytics
npx wrangler d1 migrations apply honeypot-analytics --remote
```

Update both Wrangler configs with the returned D1 database ID:

- `wrangler.jsonc`
- `apps/cloudflare-indexer/wrangler.jsonc`

Deploy indexer and Pages:

```sh
npm run deploy -w @honeypot/cloudflare-indexer
npm run build -w @honeypot/dashboard
npx wrangler pages deploy apps/dashboard/dist --project-name honeypot-sec --branch production
```

Configure:

- `dashboard.example.com` as the Cloudflare Pages custom domain.
- `legacy-dashboard.example.com` as a legacy redirect to `dashboard.example.com`.
- `honeypot.example.com` DNS A/AAAA record to the VPS.
- R2 event notifications to the `honeypot-r2-events` queue if Wrangler does not create them automatically.
- PCAP chunks remain under the private `private-pcap/` R2 prefix and expire after 14 days via the indexer cron.

## VPS

The VPS is only for the honeypot.

Generate secrets:

```sh
openssl rand -hex 32
```

Set `.env`:

```sh
INGEST_HMAC_SECRET=...
COLLECTOR_URL=http://127.0.0.1:3100/internal/ingest/events
CLOUDFLARE_INGEST_URL=https://honeypot-r2-indexer.example.workers.dev/internal/ingest/events
CLOUDFLARE_PCAP_INGEST_URL=https://honeypot-r2-indexer.example.workers.dev/internal/ingest/pcap
TRAP_TLS_KEY_PATH=/run/honeypot/tls/privkey.pem
TRAP_TLS_CERT_PATH=/run/honeypot/tls/fullchain.pem
CAPTURE_INTERFACE=enp1s0
PUBLIC_IP=203.0.113.20
ADMIN_SSH_PORT=22222
GENERIC_BANNER_PORT=65000
SUPPRESSED_SOURCE_IPS=203.0.113.10
INGEST_TIMEOUT_MS=8000
INGEST_CONCURRENCY=4
INGEST_QUEUE_MAX=5000
```

Deploy:

```sh
docker compose up -d --build
./scripts/verify-safety.sh
```

Install host-wide network capture after the Docker stack is healthy:

```sh
npm run build -w @honeypot/network-capture
./scripts/install-network-capture.sh
install -m 0644 deploy/systemd/honeypot-network-capture.service /etc/systemd/system/honeypot-network-capture.service
systemctl daemon-reload
systemctl enable --now honeypot-network-capture
./scripts/verify-network-capture.sh
```

The `r2-writer` service is bound to `127.0.0.1:3100` for host capture metadata. Docker sensors still use their Compose-internal `http://r2-writer:3100` collector URL. Full PCAP chunk uploads go directly to the Cloudflare PCAP ingest endpoint.

Rollback host capture rules:

```sh
systemctl disable --now honeypot-network-capture
./scripts/rollback-network-capture.sh
```

Enable Cowrie only after accepting that public `22` and `23` are decoy ports:

```sh
docker compose --profile cowrie up -d --build
```

## Acceptance Checks

- `curl http://honeypot.example.com/` returns the DesktopC decoy website.
- `curl http://honeypot.example.com/.env` returns a decoy config response and creates an R2 object.
- `nc honeypot.example.com 21` returns an FTP banner and creates an R2 object.
- Cloudflare indexer writes new R2 events into D1.
- `https://dashboard.example.com/api/live` shows recent sanitized events.
- `https://dashboard.example.com` shows live attacks, search, IP drilldowns, and exports.
- Public dashboard responses never include raw passwords, authorization headers, cookies, or R2 object keys.
- `ssh -p 22222 root@203.0.113.20` remains reachable after capture rules are installed.
- `203.0.113.10` is excluded by tcpdump BPF, raw-table metadata rules, local app checks, and Cloudflare ingest suppression.
- UDP DNS replies from the VPS resolver are filtered from host capture metadata and PCAP to avoid logging the honeypot's own outbound ingest lookups as inbound attacks.
- `https://dashboard.example.com/api/v1/network` shows network metadata, and `https://dashboard.example.com/api/exports/network.csv` contains no R2 keys or raw PCAP bytes.
