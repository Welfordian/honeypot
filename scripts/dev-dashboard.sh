#!/usr/bin/env bash
# Local dashboard dev: Vite (HMR) + wrangler Pages Functions (D1/R2) + live-stream worker.
#
# Open http://127.0.0.1:5173 — API and WebSocket traffic is proxied to Wrangler.
#
# Usage:
#   ./scripts/dev-dashboard.sh              # local D1/R2 (empty until you ingest or seed)
#   ./scripts/dev-dashboard.sh --remote     # remote D1/R2 via wrangler.dev.jsonc
#   ./scripts/dev-dashboard.sh --remote --skip-migrate
#
# Optional env:
#   PAGES_PORT=8788  LIVE_STREAM_PORT=8789  VITE_PORT=5173
#   Copy .dev.vars.example → .dev.vars for INDEXER_* / RESEARCHER_* secrets.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PAGES_PORT="${PAGES_PORT:-8788}"
LIVE_STREAM_PORT="${LIVE_STREAM_PORT:-8789}"
VITE_PORT="${VITE_PORT:-5173}"
USE_REMOTE=0
SKIP_MIGRATE=0
WRANGLER_CONFIG="$ROOT/wrangler.jsonc"
WRANGLER_ORIGINAL="$(mktemp)"
cp "$WRANGLER_CONFIG" "$WRANGLER_ORIGINAL"

restore_wrangler_config() {
  if [[ -f "$WRANGLER_ORIGINAL" ]]; then
    cp "$WRANGLER_ORIGINAL" "$WRANGLER_CONFIG"
    rm -f "$WRANGLER_ORIGINAL"
  fi
}

for arg in "$@"; do
  case "$arg" in
    --remote) USE_REMOTE=1 ;;
    --skip-migrate) SKIP_MIGRATE=1 ;;
    -h|--help)
      sed -n '2,13p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg (try --remote or --help)" >&2
      exit 1
      ;;
  esac
done

trap restore_wrangler_config EXIT INT TERM

ENV_FILE_FLAG=()
if [[ -f .dev.vars ]]; then
  ENV_FILE_FLAG=(--env-file .dev.vars)
fi

if [[ "$USE_REMOTE" -eq 1 ]]; then
  cp "$ROOT/wrangler.dev.jsonc" "$WRANGLER_CONFIG"
  echo "Using remote D1 and R2 bindings (wrangler.dev.jsonc → wrangler.jsonc for this session)."
  if [[ "$SKIP_MIGRATE" -eq 0 ]]; then
    echo "Applying pending remote D1 migrations..."
    if ((${#ENV_FILE_FLAG[@]})); then
      npx wrangler d1 migrations apply honeypot-analytics --remote "${ENV_FILE_FLAG[@]}"
    else
      npx wrangler d1 migrations apply honeypot-analytics --remote
    fi
  else
    echo "Skipping remote migrations (--skip-migrate)."
  fi
else
  echo "Applying local D1 migrations..."
  if ((${#ENV_FILE_FLAG[@]})); then
    npx wrangler d1 migrations apply honeypot-analytics --local "${ENV_FILE_FLAG[@]}" || true
  else
    npx wrangler d1 migrations apply honeypot-analytics --local || true
  fi
fi

pages_cmd=(
  npx wrangler pages dev apps/dashboard/dev-static
  --port "$PAGES_PORT"
  --ip 127.0.0.1
)
if [[ "$USE_REMOTE" -ne 1 ]]; then
  pages_cmd+=(--persist-to .wrangler/state)
fi
if ((${#ENV_FILE_FLAG[@]})); then
  pages_cmd+=("${ENV_FILE_FLAG[@]}")
fi

export VITE_PAGES_PROXY_TARGET="http://127.0.0.1:${PAGES_PORT}"
export VITE_LIVE_STREAM_PROXY_TARGET="http://127.0.0.1:${LIVE_STREAM_PORT}"
export VITE_PORT

echo ""
echo "Dashboard UI:  http://127.0.0.1:${VITE_PORT}"
echo "Pages API:     http://127.0.0.1:${PAGES_PORT}/api/..."
echo "Live stream:   ws://127.0.0.1:${VITE_PORT}/api/live-stream (proxied → :${LIVE_STREAM_PORT})"
echo ""

printf -v pages_shell '%q ' "${pages_cmd[@]}"
pages_shell=${pages_shell% }

live_cmd="npx wrangler dev --config apps/live-stream/wrangler.jsonc --port ${LIVE_STREAM_PORT} --ip 127.0.0.1 --persist-to .wrangler/state"
vite_cmd="npm run dev -w @honeypot/dashboard"

exec npx concurrently \
  --kill-others-on-fail \
  -n pages,live,vite \
  -c blue,magenta,green \
  "${pages_shell}" \
  "${live_cmd}" \
  "${vite_cmd}"
