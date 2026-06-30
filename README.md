# HoneyPot

A split honeypot system:

- Honeypot VPS hostname points at a single-purpose server running safe decoy services.
- The VPS only captures events and forwards signed telemetry to a Cloudflare Worker.
- The Cloudflare Worker writes immutable raw event objects to R2 and indexes public-safe metadata into D1.
- The public dashboard lives on Cloudflare Pages/Functions (e.g. `https://dashboard.example.com`).

The VPS has no analytics database, no dashboard, and no production-network role.

## What ships

- Public decoy website served by the HTTP/HTTPS trap on the VPS.
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

The dashboard UI alone (no API data) runs with:

```sh
npm run dev:dashboard
```

For a full local stack — Vite HMR, Pages Functions with D1/R2 bindings, and the live-stream WebSocket — use:

```sh
npm run dev:cloudflare
```

Open `http://127.0.0.1:5173`. API requests are proxied to `wrangler pages dev`; `/api/live-stream` is proxied to the live-stream worker.

- **Local bindings** (default): applies D1 migrations to `.wrangler/state`. The DB is empty until events are ingested or you seed data.
- **Production data**: `npm run dev:cloudflare -- --remote` swaps in `wrangler.dev.jsonc` (`remote: true` on D1/R2) for the dev session. Requires `wrangler login`. Pass `--skip-migrate` if the remote schema is already current.
- **Secrets** (hunts admin, researcher endpoints): copy `.dev.vars.example` to `.dev.vars`.

## Cloudflare Setup

Create the storage/index resources:

```sh
npx wrangler r2 bucket create honeypot-events
npx wrangler d1 create honeypot-analytics
npx wrangler d1 migrations apply honeypot-analytics --remote
```

Set the D1 database ID in **both** `wrangler.jsonc` and `apps/cloudflare-indexer/wrangler.jsonc` (`database_id`: replace `replace-with-d1-database-id` with the UUID from `wrangler d1 create`). Wrangler reads these configs at deploy time — the `D1_DATABASE_ID` placeholder in `.env.example` is for local reference only and must match the same UUID if you use it.

Deploy the indexer:

```sh
npm run deploy -w @honeypot/cloudflare-indexer
```

Deploy the public dashboard to Cloudflare Pages:

```sh
npm run build -w @honeypot/dashboard
npx wrangler pages deploy apps/dashboard/dist --project-name honeypot-sec --branch production
```

Point your dashboard hostname (e.g. `dashboard.example.com`) at the Pages project and your honeypot DNS at the VPS.

## VPS Deployment

The VPS is single-purpose. Public ports can be dedicated to decoys.

1. Set DNS for your honeypot hostname to the VPS IP.
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
- `/api/v1/reputation/ips/:ip` — GreyNoise classification (cached 24h)
- `/api/v1/reputation/payloads/:sha256` — VirusTotal detection stats (cached 24h)

Optional Wrangler secrets for external reputation overlays:

```sh
npx wrangler pages secret put GREYNOISE_API_KEY --project-name honeypot-sec
npx wrangler pages secret put VIRUSTOTAL_API_KEY --project-name honeypot-sec
```

Raw R2 objects and private PCAP chunks are not exposed by the dashboard.
