#!/usr/bin/env sh
# Download the IPinfo Lite MMDB and upload it to the honeypot-events R2 bucket.
#
# Usage:
#   IPINFO_TOKEN=your_token ./scripts/sync-ipinfo-mmdb.sh
#
# Requires: curl, npx (wrangler), and Cloudflare credentials for wrangler.

set -eu

BUCKET="${BUCKET:-honeypot-events}"
R2_KEY="${R2_KEY:-geo/ipinfo_lite.mmdb}"
WRANGLER_CONFIG="${WRANGLER_CONFIG:-apps/cloudflare-indexer/wrangler.jsonc}"
TMP_FILE="$(mktemp /tmp/ipinfo_lite.XXXXXX.mmdb)"
trap 'rm -f "$TMP_FILE"' EXIT

if [ -z "${IPINFO_TOKEN:-}" ]; then
  echo "IPINFO_TOKEN is required" >&2
  exit 1
fi

echo "Downloading IPinfo Lite MMDB..."
curl -fsSL "https://ipinfo.io/data/ipinfo_lite.mmdb?token=${IPINFO_TOKEN}" -o "$TMP_FILE"

echo "Uploading to R2: ${BUCKET}/${R2_KEY}"
npx wrangler r2 object put "${BUCKET}/${R2_KEY}" \
  --file "$TMP_FILE" \
  --content-type application/octet-stream \
  -c "$WRANGLER_CONFIG"

echo "Done."
