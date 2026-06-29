#!/usr/bin/env sh
set -eu

NETWORK_NAMES="${NETWORK_NAMES:-honeypot_honeypot_internal honeypot_honeypot_public}"
SUPPRESSED_SOURCE_IPS="${SUPPRESSED_SOURCE_IPS:-203.0.113.10}"
SUPPRESSED_SOURCE_WEB_PORTS="${SUPPRESSED_SOURCE_WEB_PORTS:-80,443}"
TCP_TRAP_PORTS="${TCP_TRAP_PORTS:-21,22,23,25,445,1433,3306,3389,5900,6379,8080}"
UDP_TRAP_PORTS="${UDP_TRAP_PORTS:-69,161}"

echo "Installing DOCKER-USER egress deny rules for $NETWORK_NAMES"
POSITION=1
WEB_PORTS="$(printf '%s' "$SUPPRESSED_SOURCE_WEB_PORTS" | tr ',' ' ')"

for SOURCE_IP in $SUPPRESSED_SOURCE_IPS; do
  for WEB_PORT in $WEB_PORTS; do
    iptables -C DOCKER-USER -s "$SOURCE_IP" -p tcp -m conntrack --ctorigdstport "$WEB_PORT" -j ACCEPT 2>/dev/null || \
      iptables -I DOCKER-USER "$POSITION" -s "$SOURCE_IP" -p tcp -m conntrack --ctorigdstport "$WEB_PORT" -j ACCEPT
    POSITION=$((POSITION + 1))
  done

  iptables -C INPUT -s "$SOURCE_IP" -p tcp -m multiport --dports "$TCP_TRAP_PORTS" -j DROP 2>/dev/null || \
    iptables -I INPUT 1 -s "$SOURCE_IP" -p tcp -m multiport --dports "$TCP_TRAP_PORTS" -j DROP
  iptables -C INPUT -s "$SOURCE_IP" -p udp -m multiport --dports "$UDP_TRAP_PORTS" -j DROP 2>/dev/null || \
    iptables -I INPUT 1 -s "$SOURCE_IP" -p udp -m multiport --dports "$UDP_TRAP_PORTS" -j DROP
  iptables -C DOCKER-USER -s "$SOURCE_IP" -j DROP 2>/dev/null || \
    iptables -I DOCKER-USER "$POSITION" -s "$SOURCE_IP" -j DROP
  POSITION=$((POSITION + 1))
done

iptables -C DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -I DOCKER-USER "$POSITION" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
POSITION=$((POSITION + 1))

for NETWORK_NAME in $NETWORK_NAMES; do
  SUBNET="$(docker network inspect "$NETWORK_NAME" -f '{{(index .IPAM.Config 0).Subnet}}')"

  if [ -z "$SUBNET" ] || [ "$SUBNET" = "<no value>" ]; then
    echo "Could not resolve subnet for $NETWORK_NAME" >&2
    exit 1
  fi

  iptables -C DOCKER-USER -s "$SUBNET" -d "$SUBNET" -j ACCEPT 2>/dev/null || \
    iptables -I DOCKER-USER "$POSITION" -s "$SUBNET" -d "$SUBNET" -j ACCEPT
  POSITION=$((POSITION + 1))

  iptables -C DOCKER-USER -s "$SUBNET" -j DROP 2>/dev/null || \
    iptables -I DOCKER-USER "$POSITION" -s "$SUBNET" -j DROP
  POSITION=$((POSITION + 1))
done

echo "Installed. Verify with: iptables -S DOCKER-USER"
