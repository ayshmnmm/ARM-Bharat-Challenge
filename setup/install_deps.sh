#!/usr/bin/env bash
# Installs NetWatch system dependencies:
#   suricata     - packet sensor (flow/DNS/TLS/HTTP/DHCP records). Its stock service is MASKED
#                  before install: the stock config captures on eth0, which we must never do.
#                  NetWatch runs it with its own wlan0-only config later.
#   jq           - JSON inspection
#   cmake, ninja-build, python3-dev - building the ExecuTorch Llama runner
#
# Verifies routing/firewall unchanged, eth0 not promiscuous, and no new listeners.
# Run as your normal user:  bash setup/install_deps.sh
set -euo pipefail
if [[ $EUID -eq 0 ]]; then echo "Run as your normal user; the script calls sudo itself." >&2; exit 1; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=setup/netsafety.sh
source "$HERE/netsafety.sh"
SNAP="$HERE/netsnap/deps"

echo "== 1/4 Snapshot network state (before)"
sudo -v
rm -rf "$SNAP"; netsafety_snapshot "$SNAP/before"

echo "== 2/4 Mask stock suricata service so it can never start on eth0"
sudo systemctl mask suricata.service

echo "== 3/4 Install packages (no recommends: no rule downloader, no snort rules)"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  suricata jq cmake ninja-build python3-dev

echo "== 4/4 Verify"
if systemctl is-active --quiet suricata.service || pgrep -x Suricata-Main >/dev/null || pgrep -x suricata >/dev/null; then
  echo "!! suricata is running; stopping it" >&2; sudo systemctl stop suricata.service || true; sudo pkill -x suricata || true; exit 1
fi
echo "OK: stock suricata service masked and not running ($(suricata -V 2>&1 | head -1))"
netsafety_snapshot "$SNAP/after"
netsafety_diff "$SNAP/before" "$SNAP/after"
netsafety_new_listeners_ok "$SNAP/listeners.before"
netsafety_eth0_not_promisc
echo "Done."
