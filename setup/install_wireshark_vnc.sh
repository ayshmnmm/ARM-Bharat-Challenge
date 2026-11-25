#!/usr/bin/env bash
# Installs Wireshark/tshark plus a headless, localhost-only TigerVNC desktop (Openbox).
#
# Hard constraints (router on this Pi, eth0 monitored by campus IT):
#   - no listening port on eth0 (VNC binds 127.0.0.1/::1 only; reach it via SSH tunnel over wlan0)
#   - no routing / firewall / sysctl / NetworkManager / dnsmasq / hostapd changes
#   - Wireshark: eth0 hidden, DNS/external name resolution off (no lookups leave the box)
# A before/after snapshot of routes, rules and forwarding sysctls is diffed at the end.
#
# Run as your normal user (not with sudo):  bash setup/install_wireshark_vnc.sh
set -euo pipefail

if [[ $EUID -eq 0 ]]; then echo "Run as your normal user; the script calls sudo itself." >&2; exit 1; fi

ME="$USER"
SNAP="$(cd "$(dirname "$0")" && pwd)/netsnap"
VNC_DISPLAY=":1"
VNC_PORT=5901

snapshot() {
  local d="$SNAP/$1"; mkdir -p "$d"
  ip route show table all          > "$d/routes"
  ip rule                          > "$d/rules"
  ip -br addr                      > "$d/addr"
  sudo iptables -S                 > "$d/iptables"
  sudo ip6tables -S                > "$d/ip6tables"
  # -t: omit set elements; the router's dynamic sets (timeout 10m) churn with LAN traffic
  sudo nft -s -t list ruleset      > "$d/nft"
  sysctl -a 2>/dev/null | grep -E '^net\.ipv[46]\.(ip_forward|conf\.(all|eth0|wlan0)\.forwarding)' > "$d/sysctl"
  systemctl is-active NetworkManager dnsmasq hostapd netfilter-persistent > "$d/services" || true
}

echo "== 1/6 Snapshot network state (before)"
sudo -v
snapshot before

echo "== 2/6 Install packages (no recommends, so no network GUI tools get pulled in)"
# Note: the .deb downloads go out through the Pi's default route like any apt run.
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  wireshark tshark tigervnc-standalone-server tigervnc-tools openbox xterm dbus-x11
sudo usermod -aG wireshark "$ME"

echo "== 3/6 Wireshark prefs: default wlan0, hide eth0, no network name resolution"
mkdir -p ~/.config/wireshark
if [[ -e ~/.config/wireshark/preferences ]]; then
  echo "   ~/.config/wireshark/preferences exists, leaving it alone"
else
  cat > ~/.config/wireshark/preferences <<'EOF'
# netwatch: capture on our own Wi-Fi LAN only; never touch the campus (eth0) side.
capture.device: wlan0
capture.devices_hide: eth0,CloudflareWARP,any
# Resolve MACs/ports from local files only; never send DNS lookups.
nameres.mac_name: TRUE
nameres.transport_name: TRUE
nameres.network_name: FALSE
nameres.dns_pkt_addr_resolution: FALSE
nameres.use_external_name_resolver: FALSE
EOF
fi

echo "== 4/6 TigerVNC: localhost-only Openbox session on $VNC_DISPLAY"
mkdir -p ~/.config/tigervnc ~/.config/openbox
cat > ~/.config/tigervnc/config <<'EOF'
session=openbox
geometry=1600x900
localhost=yes
SecurityTypes=VncAuth
EOF
[[ -e ~/.config/openbox/autostart ]] || echo 'xterm &' > ~/.config/openbox/autostart
if [[ ! -s ~/.config/tigervnc/passwd ]]; then
  echo "   Set a VNC password (view-only password: answer n)"
  vncpasswd ~/.config/tigervnc/passwd
fi
grep -qE "^${VNC_DISPLAY}=" /etc/tigervnc/vncserver.users \
  || echo "${VNC_DISPLAY}=${ME}" | sudo tee -a /etc/tigervnc/vncserver.users >/dev/null
sudo systemctl enable --now "tigervncserver@${VNC_DISPLAY}"
sleep 3

echo "== 5/6 Check VNC listens on loopback only"
listen=$(ss -Htln "sport = :$VNC_PORT" | awk '{print $4}')
echo "$listen"
if [[ -z "$listen" ]]; then
  echo "!! VNC is not listening; check: journalctl -u tigervncserver@${VNC_DISPLAY}" >&2
elif grep -vqE '^(127\.0\.0\.1|\[::1\]):' <<<"$listen"; then
  echo "!! VNC bound beyond loopback, stopping it" >&2
  sudo systemctl disable --now "tigervncserver@${VNC_DISPLAY}"; exit 1
fi

echo "== 6/6 Snapshot network state (after) and diff"
snapshot after
if diff -ru "$SNAP/before" "$SNAP/after"; then
  echo "OK: routes, rules, firewall, forwarding and router services unchanged."
else
  echo "!! Network state differs (diff above). Nothing was meant to change; investigate." >&2; exit 1
fi

cat <<EOF

Done. Log out/in (or reboot) so the 'wireshark' group applies to new sessions.
From the Ubuntu VM (on the Pi's Wi-Fi):
  ssh -L ${VNC_PORT}:localhost:${VNC_PORT} ${ME}@192.168.1.1
  then point a VNC viewer at localhost:${VNC_PORT}
EOF
