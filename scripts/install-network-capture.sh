#!/usr/bin/env sh
set -eu

CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-enp1s0}"
SUPPRESSED_SOURCE_IPS="${SUPPRESSED_SOURCE_IPS:-203.0.113.10}"
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-22222}"
GENERIC_BANNER_PORT="${GENERIC_BANNER_PORT:-65000}"
RESERVED_TCP_PORTS="${RESERVED_TCP_PORTS:-21,22,23,25,80,443,445,1433,3306,3389,5900,6379,8080,$ADMIN_SSH_PORT,$GENERIC_BANNER_PORT}"

iptables -C INPUT -p tcp --dport "$ADMIN_SSH_PORT" -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -p tcp --dport "$ADMIN_SSH_PORT" -j ACCEPT

POSITION=1
for SOURCE_IP in $SUPPRESSED_SOURCE_IPS; do
  iptables -C INPUT -s "$SOURCE_IP" -p tcp --dport "$ADMIN_SSH_PORT" -j ACCEPT 2>/dev/null || \
    iptables -I INPUT "$POSITION" -s "$SOURCE_IP" -p tcp --dport "$ADMIN_SSH_PORT" -j ACCEPT
  POSITION=$((POSITION + 1))

  iptables -C INPUT -s "$SOURCE_IP" -j DROP 2>/dev/null || \
    iptables -I INPUT "$POSITION" -s "$SOURCE_IP" -j DROP
  POSITION=$((POSITION + 1))

  iptables -t nat -C PREROUTING -s "$SOURCE_IP" -j RETURN 2>/dev/null || \
    iptables -t nat -I PREROUTING 1 -s "$SOURCE_IP" -j RETURN
done

iptables -C INPUT -i "$CAPTURE_INTERFACE" -p tcp --dport "$GENERIC_BANNER_PORT" -j ACCEPT 2>/dev/null || \
  iptables -I INPUT "$POSITION" -i "$CAPTURE_INTERFACE" -p tcp --dport "$GENERIC_BANNER_PORT" -j ACCEPT

iptables -t nat -C PREROUTING -i "$CAPTURE_INTERFACE" -p tcp -m multiport ! --dports "$RESERVED_TCP_PORTS" -j REDIRECT --to-ports "$GENERIC_BANNER_PORT" 2>/dev/null || \
  iptables -t nat -I PREROUTING 2 -i "$CAPTURE_INTERFACE" -p tcp -m multiport ! --dports "$RESERVED_TCP_PORTS" -j REDIRECT --to-ports "$GENERIC_BANNER_PORT"

iptables -t raw -N HONEYPOT_CAPTURE 2>/dev/null || true
iptables -t raw -F HONEYPOT_CAPTURE

for SOURCE_IP in $SUPPRESSED_SOURCE_IPS; do
  iptables -t raw -A HONEYPOT_CAPTURE -s "$SOURCE_IP" -j RETURN
done

iptables -t raw -A HONEYPOT_CAPTURE -p tcp --dport "$ADMIN_SSH_PORT" -j RETURN
iptables -t raw -A HONEYPOT_CAPTURE -p tcp --syn -j LOG --log-prefix "HP_CAPTURE: " --log-level 6
iptables -t raw -A HONEYPOT_CAPTURE -p udp ! --sport 53 -m hashlimit --hashlimit-name hp_udp_capture --hashlimit-upto 10/second --hashlimit-burst 20 --hashlimit-mode srcip,dstport -j LOG --log-prefix "HP_CAPTURE: " --log-level 6
iptables -t raw -A HONEYPOT_CAPTURE -p icmp -m hashlimit --hashlimit-name hp_icmp_capture --hashlimit-upto 10/second --hashlimit-burst 20 --hashlimit-mode srcip -j LOG --log-prefix "HP_CAPTURE: " --log-level 6
iptables -t raw -A HONEYPOT_CAPTURE -j RETURN

iptables -t raw -C PREROUTING -i "$CAPTURE_INTERFACE" -j HONEYPOT_CAPTURE 2>/dev/null || \
  iptables -t raw -I PREROUTING 1 -i "$CAPTURE_INTERFACE" -j HONEYPOT_CAPTURE

install -d -m 700 /var/spool/honeypot-capture

echo "Installed network capture rules."
echo "Verify with: scripts/verify-network-capture.sh"
