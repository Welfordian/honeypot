#!/usr/bin/env sh
set -eu

DOMAIN="${CERT_DOMAIN:-honeypot.example.com}"
LE_LIVE_DIR="${LE_LIVE_DIR:-/etc/letsencrypt/live/$DOMAIN}"
TARGET_DIR="${TARGET_DIR:-/opt/honeypot/certs/$DOMAIN}"
PROJECT_DIR="${PROJECT_DIR:-/opt/honeypot}"

install -d -m 0750 "$TARGET_DIR"
install -m 0444 "$LE_LIVE_DIR/fullchain.pem" "$TARGET_DIR/fullchain.pem"
install -m 0400 "$LE_LIVE_DIR/privkey.pem" "$TARGET_DIR/privkey.pem"
chown 1000:1000 "$TARGET_DIR" "$TARGET_DIR/fullchain.pem" "$TARGET_DIR/privkey.pem"

if command -v docker >/dev/null 2>&1 && [ -f "$PROJECT_DIR/docker-compose.yml" ]; then
  cd "$PROJECT_DIR"
  docker compose up -d --no-deps --force-recreate --build trap-web
fi
