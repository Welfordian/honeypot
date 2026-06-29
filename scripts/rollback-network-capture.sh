#!/usr/bin/env sh
set -eu

CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-enp1s0}"
SUPPRESSED_SOURCE_IPS="${SUPPRESSED_SOURCE_IPS:-203.0.113.10}"
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-22222}"
GENERIC_BANNER_PORT="${GENERIC_BANNER_PORT:-65000}"
RESERVED_TCP_PORTS="${RESERVED_TCP_PORTS:-21,22,23,25,80,443,445,1433,3306,3389,5900,6379,8080,$ADMIN_SSH_PORT,$GENERIC_BANNER_PORT}"

while iptables -t raw -C PREROUTING -i "$CAPTURE_INTERFACE" -j HONEYPOT_CAPTURE 2>/dev/null; do
  iptables -t raw -D PREROUTING -i "$CAPTURE_INTERFACE" -j HONEYPOT_CAPTURE
done
iptables -t raw -F HONEYPOT_CAPTURE 2>/dev/null || true
iptables -t raw -X HONEYPOT_CAPTURE 2>/dev/null || true

while iptables -t nat -C PREROUTING -i "$CAPTURE_INTERFACE" -p tcp -m multiport ! --dports "$RESERVED_TCP_PORTS" -j REDIRECT --to-ports "$GENERIC_BANNER_PORT" 2>/dev/null; do
  iptables -t nat -D PREROUTING -i "$CAPTURE_INTERFACE" -p tcp -m multiport ! --dports "$RESERVED_TCP_PORTS" -j REDIRECT --to-ports "$GENERIC_BANNER_PORT"
done

for SOURCE_IP in $SUPPRESSED_SOURCE_IPS; do
  while iptables -t nat -C PREROUTING -s "$SOURCE_IP" -j RETURN 2>/dev/null; do
    iptables -t nat -D PREROUTING -s "$SOURCE_IP" -j RETURN
  done
  while iptables -C INPUT -s "$SOURCE_IP" -j DROP 2>/dev/null; do
    iptables -D INPUT -s "$SOURCE_IP" -j DROP
  done
done

while iptables -C INPUT -i "$CAPTURE_INTERFACE" -p tcp --dport "$GENERIC_BANNER_PORT" -j ACCEPT 2>/dev/null; do
  iptables -D INPUT -i "$CAPTURE_INTERFACE" -p tcp --dport "$GENERIC_BANNER_PORT" -j ACCEPT
done

echo "Rolled back network capture rules."
