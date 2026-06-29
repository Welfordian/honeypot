# HoneyPot

A split honeypot system:

- `honeypot.example.com` points at a single-purpose VPS running safe decoy services.
- The VPS only captures events and forwards signed telemetry to a Cloudflare Worker.
- The Cloudflare Worker writes immutable raw event objects to R2 and indexes public-safe metadata into D1.
- The public dashboard lives on Cloudflare Pages/Functions at `dashboard.example.com`.

The VPS has no analytics database, no dashboard, and no production-network role.

## What ships

- Public `honeypot.example.com` decoy website served by the HTTP/HTTPS trap.
- HTTP/HTTPS traps for fake admin, CMS, API, config leak, metadata, Docker, Kubernetes, Jenkins, Grafana, Laravel, and generic exploit probes.
- TCP/UDP traps for FTP, SMTP, HTTP proxy, MySQL, MSSQL, Redis, RDP, SMB, VNC, SNMP, and TFTP.
- Host-wide network capture for inbound attempts on all ports, with private 14-day PCAP chunks and public-safe metadata analytics.
- Generic TCP banner sink for otherwise-unused TCP ports.
- Optional Cowrie SSH/Telnet profile plus a JSON log shipper.
- VPS-local ingest gateway with HMAC-authenticated internal ingestion and signed Cloudflare forwarding.
- R2 event-notification indexer Worker that reads raw objects and writes sanitized metadata to D1.
- Public React dashboard with overview charts, live attack polling, IP search, event-type filtering, IP drilldowns, payload-hash summaries, and blocklist export.

## Local Development

```sh
npm install
cp .env.example .env
npm test
npm run typecheck
npm run build
```

The Cloudflare Pages dashboard can run locally with:

```sh
npm run dev:dashboard
```

For full local Cloudflare binding emulation, build the dashboard and run:

```sh
npm run build -w @honeypot/dashboard
npx wrangler pages dev apps/dashboard/dist
```

## Cloudflare Setup

Create the storage/index resources:

```sh
npx wrangler r2 bucket create honeypot-events
npx wrangler d1 create honeypot-analytics
npx wrangler d1 migrations apply honeypot-analytics --remote
```

Replace `REPLACE_WITH_D1_DATABASE_ID` in `wrangler.jsonc` and `apps/cloudflare-indexer/wrangler.jsonc`.

Deploy the indexer:

```sh
npm run deploy -w @honeypot/cloudflare-indexer
```

Deploy the public dashboard to Cloudflare Pages:

```sh
npm run build -w @honeypot/dashboard
npx wrangler pages deploy apps/dashboard/dist --project-name honeypot-sec --branch production
```

Point `dashboard.example.com` at the Pages project and `honeypot.example.com` at the VPS.

## VPS Deployment

The VPS is single-purpose. Public ports can be dedicated to decoys.

1. Set DNS for `honeypot.example.com` to the VPS IP.
2. Copy `.env.example` to `.env` and set `INGEST_HMAC_SECRET` and `CLOUDFLARE_INGEST_URL`.
3. Start the VPS stack:

```sh
docker compose up -d --build
```

4. Optionally enable SSH/Telnet honeypot ports:

```sh
docker compose --profile cowrie up -d --build
```

5. Enable host-wide network capture:

```sh
npm run build -w @honeypot/network-capture
sudo install -d -m 755 /opt/honeypot
sudo cp -R apps packages node_modules package.json package-lock.json /opt/honeypot/
sudo cp .env /opt/honeypot/.env
sudo cp deploy/systemd/honeypot-network-capture.service /etc/systemd/system/
sudo ./scripts/install-network-capture.sh
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-network-capture
sudo ./scripts/verify-network-capture.sh
```

6. Verify safety:

```sh
./scripts/verify-safety.sh
```

## Public API

Cloudflare Pages Functions expose public, sanitized APIs:

- `/api/live`
- `/api/events?ip=203.0.113.10&eventType=http&sinceHours=24`
- `/api/analytics/overview`
- `/api/ips`
- `/api/ips/:ip`
- `/api/payloads`
- `/api/traps/health`
- `/api/exports/blocklist.txt`
- `/api/v1/network`
- `/api/exports/network.csv`

Raw R2 objects and private PCAP chunks are not exposed by the dashboard.
