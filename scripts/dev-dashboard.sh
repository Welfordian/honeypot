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
#   D1_DATABASE_ID=... for --remote, or let Wrangler discover it by database name.
#   Copy .dev.vars.example → .dev.vars for D1_DATABASE_ID / INDEXER_* / RESEARCHER_* secrets.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PAGES_PORT="${PAGES_PORT:-8788}"
LIVE_STREAM_PORT="${LIVE_STREAM_PORT:-8789}"
VITE_PORT="${VITE_PORT:-5173}"
USE_REMOTE=0
SKIP_MIGRATE=0
WRANGLER_CONFIG="$ROOT/wrangler.jsonc"
WRANGLER_SESSION_CONFIG="$WRANGLER_CONFIG"
D1_DATABASE_NAME="${D1_DATABASE_NAME:-honeypot-analytics}"
WRANGLER_ORIGINAL=""

restore_wrangler_config() {
  if [[ -n "$WRANGLER_ORIGINAL" && -f "$WRANGLER_ORIGINAL" ]]; then
    cp "$WRANGLER_ORIGINAL" "$WRANGLER_CONFIG"
    rm -f "$WRANGLER_ORIGINAL"
  fi
}

backup_wrangler_config() {
  if [[ -z "$WRANGLER_ORIGINAL" ]]; then
    WRANGLER_ORIGINAL="$(mktemp)"
    cp "$WRANGLER_CONFIG" "$WRANGLER_ORIGINAL"
  fi
}

read_dev_var() {
  local key="$1"
  [[ -f .dev.vars ]] || return 1
  awk -v key="$key" '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
      line=$0
      sub(/^[[:space:]]*/, "", line)
      split(line, parts, "=")
      if (parts[1] == key) {
        sub(/^[^=]*=/, "", line)
        print line
      }
    }
  ' .dev.vars | tail -n 1
}

strip_quotes() {
  local value="$1"
  value="${value%$'\r'}"
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "$value"
}

resolve_d1_database_id() {
  local configured="${D1_DATABASE_ID:-}"
  if [[ -z "$configured" ]]; then
    configured="$(read_dev_var D1_DATABASE_ID || true)"
    configured="$(strip_quotes "$configured")"
  fi

  if [[ -n "$configured" && "$configured" != replace-* && "$configured" != "replace-with-d1-database-id" ]]; then
    printf '%s' "$configured"
    return 0
  fi

  npx wrangler d1 list --json | node -e '
    const name = process.argv[1];
    let input = "";
    process.stdin.on("data", (chunk) => { input += chunk; });
    process.stdin.on("end", () => {
      const parsed = JSON.parse(input);
      const databases = Array.isArray(parsed) ? parsed : parsed.result ?? [];
      const db = databases.find((candidate) => candidate.name === name || candidate.database_name === name);
      const id = db?.uuid ?? db?.id ?? db?.database_id;
      if (!id) process.exit(1);
      process.stdout.write(id);
    });
  ' "$D1_DATABASE_NAME"
}

prepare_remote_config() {
  local database_id="$1"
  local suppressed_ips="${SUPPRESSED_SOURCE_IPS:-}"

  if [[ -z "$suppressed_ips" ]]; then
    suppressed_ips="$(read_dev_var SUPPRESSED_SOURCE_IPS || true)"
    suppressed_ips="$(strip_quotes "$suppressed_ips")"
  fi

  backup_wrangler_config
  node - "$ROOT/wrangler.dev.jsonc" "$WRANGLER_CONFIG" "$database_id" "$suppressed_ips" <<'NODE'
const fs = require("node:fs");
const [source, target, databaseId, suppressedIps] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(source, "utf8"));

function patchDatabases(databases) {
  for (const database of databases ?? []) {
    if (database.database_name === "honeypot-analytics") {
      database.database_id = databaseId;
      database.remote = true;
    }
  }
}

patchDatabases(config.d1_databases);
patchDatabases(config.env?.production?.d1_databases);

if (suppressedIps) {
  config.vars = { ...(config.vars ?? {}), SUPPRESSED_SOURCE_IPS: suppressedIps };
  config.env = config.env ?? {};
  config.env.production = config.env.production ?? {};
  config.env.production.vars = { ...(config.env.production.vars ?? {}), SUPPRESSED_SOURCE_IPS: suppressedIps };
}

fs.writeFileSync(target, `${JSON.stringify(config, null, 2)}\n`);
NODE
  WRANGLER_SESSION_CONFIG="$WRANGLER_CONFIG"
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

trap restore_wrangler_config EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ENV_FILE_FLAG=()
if [[ -f .dev.vars ]]; then
  ENV_FILE_FLAG=(--env-file .dev.vars)
fi

if [[ "$USE_REMOTE" -eq 1 ]]; then
  D1_DATABASE_ID_RESOLVED="$(resolve_d1_database_id)"
  if [[ ! "$D1_DATABASE_ID_RESOLVED" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    echo "Could not resolve a valid D1 database UUID for ${D1_DATABASE_NAME}." >&2
    echo "Set D1_DATABASE_ID in your shell or .dev.vars, then retry." >&2
    exit 1
  fi

  prepare_remote_config "$D1_DATABASE_ID_RESOLVED"
  echo "Using remote D1 and R2 bindings via a generated Wrangler config restored on exit."
  if [[ "$SKIP_MIGRATE" -eq 0 ]]; then
    echo "Applying pending remote D1 migrations..."
    if ((${#ENV_FILE_FLAG[@]})); then
      npx wrangler d1 migrations apply "$D1_DATABASE_NAME" --remote --config "$WRANGLER_SESSION_CONFIG" "${ENV_FILE_FLAG[@]}"
    else
      npx wrangler d1 migrations apply "$D1_DATABASE_NAME" --remote --config "$WRANGLER_SESSION_CONFIG"
    fi
  else
    echo "Skipping remote migrations (--skip-migrate)."
  fi
else
  echo "Applying local D1 migrations..."
  if ((${#ENV_FILE_FLAG[@]})); then
    npx wrangler d1 migrations apply "$D1_DATABASE_NAME" --local --config "$WRANGLER_SESSION_CONFIG" "${ENV_FILE_FLAG[@]}" || true
  else
    npx wrangler d1 migrations apply "$D1_DATABASE_NAME" --local --config "$WRANGLER_SESSION_CONFIG" || true
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

npx concurrently \
  --kill-others-on-fail \
  -n pages,live,vite \
  -c blue,magenta,green \
  "${pages_shell}" \
  "${live_cmd}" \
  "${vite_cmd}"
