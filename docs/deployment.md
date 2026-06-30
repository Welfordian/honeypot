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

- Your dashboard hostname (e.g. `dashboard.example.com`) as the Cloudflare Pages custom domain.
- Optionally, a legacy hostname (e.g. `legacy-dashboard.example.com`) redirecting to the canonical dashboard URL.
- Honeypot VPS DNS A/AAAA record to the trap host (decoy services only).
- R2 event notifications to the `honeypot-r2-events` queue if Wrangler does not create them automatically.
- PCAP chunks remain under the private `private-pcap/` R2 prefix and expire after 14 days via the indexer cron.

### Pages / dashboard secrets

Set on the Pages project (`honeypot-sec`) or via `wrangler pages secret put`:

```sh
npx wrangler pages secret put RESEARCHER_API_TOKEN --project-name honeypot-sec
npx wrangler pages secret put INDEXER_URL --project-name honeypot-sec   # e.g. https://honeypot-r2-indexer.<account>.workers.dev
npx wrangler pages secret put INDEXER_ADMIN_TOKEN --project-name honeypot-sec
# Optional reputation providers:
npx wrangler pages secret put GREYNOISE_API_KEY --project-name honeypot-sec
npx wrangler pages secret put VIRUSTOTAL_API_KEY --project-name honeypot-sec
```

Set `PUBLIC_SITE_ORIGIN` in root `wrangler.jsonc` to your dashboard URL (e.g. `https://dashboard.example.com`) for canonical URLs in exports and feeds.
Set `SUPPRESSED_SOURCE_IPS` in both Pages and indexer Wrangler configs before deployment so suppressed sources are excluded from ingest, capture metadata, and researcher-access audit logs.

### Indexer secrets

Use the same `INGEST_HMAC_SECRET` value as the VPS `.env` so signed ingest from `r2-writer` and host capture validates on the indexer Worker.

```sh
npx wrangler secret put INGEST_HMAC_SECRET -c apps/cloudflare-indexer/wrangler.jsonc
npx wrangler secret put IPINFO_TOKEN -c apps/cloudflare-indexer/wrangler.jsonc
npx wrangler secret put INDEXER_ADMIN_TOKEN -c apps/cloudflare-indexer/wrangler.jsonc
```

Apply D1 migrations through `0008_webhook_index.sql` on remote before enabling researcher endpoints.

### IPinfo MMDB bootstrap

Country/ASN enrichment reads `geo/ipinfo_lite.mmdb` from the `honeypot-events` R2 bucket. Set an IPinfo API token on the indexer:

```sh
npx wrangler secret put IPINFO_TOKEN -c apps/cloudflare-indexer/wrangler.jsonc
```

Manual bootstrap (first deploy or if the cron has not run yet):

```sh
curl -L "https://ipinfo.io/data/ipinfo_lite.mmdb?token=$IPINFO_TOKEN" -o /tmp/ipinfo_lite.mmdb
npx wrangler r2 object put honeypot-events/geo/ipinfo_lite.mmdb --file /tmp/ipinfo_lite.mmdb --content-type application/octet-stream
```

Or use the helper script:

```sh
IPINFO_TOKEN=... ./scripts/sync-ipinfo-mmdb.sh
```

Backfill enrichment for existing IP profiles after the MMDB is in R2:

```sh
curl -X POST "https://honeypot-r2-indexer.example.workers.dev/internal/admin/backfill-enrichment" \
  -H "x-indexer-token: $INDEXER_ADMIN_TOKEN"
```

The indexer cron syncs the MMDB from IPinfo daily once `IPINFO_TOKEN` is configured.

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
sudo ./scripts/install-firewall.sh
./scripts/verify-safety.sh
```

`install-firewall.sh` installs `DOCKER-USER` egress deny rules and suppressed-source `INPUT` drops after Compose has created the honeypot Docker networks.

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

- Honeypot decoy HTTP/HTTPS responds on the VPS public hostname.
- `curl https://dashboard.example.com/api/live` shows recent sanitized events.
- `https://dashboard.example.com` shows live attacks, search (including HTTP path filter), IP drilldowns, and exports.
- Public dashboard responses never include raw passwords, authorization headers, cookies, or R2 object keys.
- `ssh -p 22222` on the VPS admin port remains reachable after capture rules are installed.
- Suppressed source IPs are excluded by tcpdump BPF, raw-table metadata rules, local app checks, and Cloudflare ingest suppression.
- UDP DNS replies from the VPS resolver are filtered from host capture metadata and PCAP to avoid logging the honeypot's own outbound ingest lookups as inbound attacks.
- `https://dashboard.example.com/api/v1/network` shows network metadata, and `https://dashboard.example.com/api/exports/network.csv` contains no R2 keys or raw PCAP bytes.
