#!/usr/bin/env sh
set -eu

CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-enp1s0}"
SUPPRESSED_SOURCE_IPS="${SUPPRESSED_SOURCE_IPS:-203.0.113.10}"
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-22222}"
GENERIC_BANNER_PORT="${GENERIC_BANNER_PORT:-65000}"

echo "Checking admin SSH listener"
ss -H -ltnp | grep ":$ADMIN_SSH_PORT "

echo "Checking generic banner listener"
ss -H -ltnp | grep ":$GENERIC_BANNER_PORT "

echo "Checking raw capture chain"
iptables -t raw -S HONEYPOT_CAPTURE
iptables -t raw -C PREROUTING -i "$CAPTURE_INTERFACE" -j HONEYPOT_CAPTURE

echo "Checking generic banner redirect"
iptables -t nat -S PREROUTING | grep -- "--to-ports $GENERIC_BANNER_PORT"

echo "Checking suppressed IP rules"
for SOURCE_IP in $SUPPRESSED_SOURCE_IPS; do
  iptables -t raw -C HONEYPOT_CAPTURE -s "$SOURCE_IP" -j RETURN
  iptables -t nat -C PREROUTING -s "$SOURCE_IP" -j RETURN
done

echo "Checking capture spool permissions"
test "$(stat -c '%a' /var/spool/honeypot-capture)" = "700"

echo "Network capture verification passed."
