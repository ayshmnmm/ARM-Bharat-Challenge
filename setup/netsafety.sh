#!/usr/bin/env bash
# Shared network-safety helpers (source this file; do not execute it).
# The Pi is a live router: these prove an install/change left routing untouched.
#
#   netsafety_snapshot <dir>         record routes, rules, firewall, forwarding, router services
#   netsafety_diff <before> <after>  non-zero exit if anything differs
#   netsafety_new_listeners_ok <before>  non-zero exit if a listener appeared beyond loopback/wlan0
#   netsafety_eth0_not_promisc       non-zero exit if eth0 is in promiscuous mode

WLAN_IP="192.168.1.1"

netsafety_snapshot() {
  local d="$1"; mkdir -p "$d"
  # The WARP client re-adds its tunnel's IPv6 link-local address/routes whenever it reconnects.
  ip route show table all | grep -vE 'fe80::[^ ]* dev CloudflareWARP' > "$d/routes"
  ip rule                          > "$d/rules"
  ip -br addr | sed -E '/^CloudflareWARP/ s/ fe80::[^ ]+//g' > "$d/addr"
  sudo iptables -S                 > "$d/iptables"
  sudo ip6tables -S                > "$d/ip6tables"
  # -t omits set elements: the router's dynamic sets churn with normal LAN traffic.
  sudo nft -s -t list ruleset      > "$d/nft"
  sysctl -a 2>/dev/null | grep -E '^net\.ipv[46]\.(ip_forward|conf\.(all|eth0|wlan0)\.forwarding)' > "$d/sysctl"
  systemctl is-active NetworkManager dnsmasq hostapd netfilter-persistent > "$d/services" || true
  _listeners > "$d/../listeners.$(basename "$d")"
}

# proto + local address; UDP ephemeral ports (avahi, DHCP clients) are dropped as they churn.
_listeners() {
  ss -Htuln | awk '{split($5,a,":"); p=a[length(a)]; if (!($1=="udp" && p+0>=32768)) print $1, $5}' | sort -u
}

netsafety_diff() {
  if diff -ru "$1" "$2"; then
    echo "OK: routes, rules, firewall, forwarding and router services unchanged."
  else
    echo "!! Network state differs (diff above). Investigate before continuing." >&2
    return 1
  fi
}

# New listeners (vs. a snapshot's listeners file) are allowed only on loopback or the wlan0 address.
netsafety_new_listeners_ok() {
  local bad
  bad=$(comm -13 "$1" <(_listeners) | awk '{print $2}' \
    | grep -vE "^(127\.[0-9.]+|\[::1\]|${WLAN_IP//./\\.}):[0-9]+$" || true)
  if [[ -n "$bad" ]]; then
    echo "!! New listeners reachable beyond wlan0/loopback:" >&2; echo "$bad" >&2; return 1
  fi
  echo "OK: no new listeners beyond loopback and ${WLAN_IP}."
}

netsafety_eth0_not_promisc() {
  if ip -d link show eth0 | grep -q 'promiscuity [1-9]'; then
    echo "!! eth0 is in promiscuous mode" >&2; return 1
  fi
  echo "OK: eth0 not in promiscuous mode."
}
