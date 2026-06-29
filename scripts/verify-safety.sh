#!/usr/bin/env sh
set -eu

echo "Checking honeypot services"
docker compose ps r2-writer trap-web tcp-traps

echo "Checking sensor privilege posture"
docker compose exec -T trap-web sh -lc 'id && test ! -S /var/run/docker.sock && echo no-docker-socket'
docker compose exec -T tcp-traps sh -lc 'id && test ! -S /var/run/docker.sock && echo no-docker-socket'

echo "Checking sensor filesystem is read-only"
docker compose exec -T trap-web sh -lc 'if touch /root/honeypot-write-test 2>/dev/null; then echo writable-root && exit 1; else echo read-only-root; fi'
docker compose exec -T tcp-traps sh -lc 'if touch /root/honeypot-write-test 2>/dev/null; then echo writable-root && exit 1; else echo read-only-root; fi'

echo "Checking sensor egress denial"
docker compose exec -T trap-web sh -lc 'if wget -T 3 -qO- http://1.1.1.1 >/dev/null 2>&1; then echo egress-open && exit 1; else echo egress-blocked; fi'
docker compose exec -T tcp-traps sh -lc 'if wget -T 3 -qO- http://1.1.1.1 >/dev/null 2>&1; then echo egress-open && exit 1; else echo egress-blocked; fi'

echo "Checking R2 writer health"
docker compose exec -T r2-writer sh -lc 'wget -qO- http://127.0.0.1:3100/health'
