#!/usr/bin/env bash
# Deploy NetWatch as three systemd services on the router:
#   netwatch-sensor  Suricata, passive capture on wlan0 only
#   netwatch-live    detection + explanations (no network access at all)
#   netwatch-web     dashboard on 192.168.1.1:8088 (kernel-fenced to the Wi-Fi LAN)
#
# Safe to re-run (updates code and restarts). Every run is wrapped in the router-safety checks;
# if any check fails, the services are stopped and disabled again.
# Undo completely with: bash setup/uninstall_services.sh
#
# Run as your normal user:  bash setup/install_services.sh
set -euo pipefail
if [[ $EUID -eq 0 ]]; then echo "Run as your normal user; the script calls sudo itself." >&2; exit 1; fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=setup/netsafety.sh
source "$REPO/setup/netsafety.sh"
SNAP="$REPO/setup/netsnap/services"
DEST=/opt/netwatch
UNITS=(netwatch-sensor netwatch-live netwatch-web)

rollback() {
  echo "!! Rolling back: stopping and disabling NetWatch services" >&2
  sudo systemctl disable --now "${UNITS[@]/%/.service}" 2>/dev/null || true
  exit 1
}

echo "== 1/7 Pre-flight"
[[ -f "$REPO/web/out/index.html" ]] || { echo "Build the dashboard first: (cd web && npx next build)" >&2; exit 1; }
ip -br addr show wlan0 | grep -q "192.168.1.1/" || { echo "wlan0 does not have 192.168.1.1" >&2; exit 1; }
sudo -v
rm -rf "$SNAP"; netsafety_snapshot "$SNAP/before"

echo "== 2/7 Service account"
id netwatch >/dev/null 2>&1 || sudo useradd --system --no-create-home --home-dir /var/lib/netwatch \
  --shell /usr/sbin/nologin netwatch

echo "== 3/7 Deploy code to $DEST (root-owned, read-only for the service)"
sudo mkdir -p "$DEST"
sudo rsync -a --delete --exclude .venv \
  --include='/netwatch/***' --include='/sensor/***' --include='/feeds/' --include='/feeds/custom/***' \
  --include='/web/' --include='/web/out/***' --include='/setup/' --include='/setup/netwatch.env' \
  --include='/models/' --include='/models/flow_classifier.joblib' --include='/models/flow_classifier.json' \
  --include='/requirements.txt' --exclude='*' "$REPO/" "$DEST/"
if [[ -e "$REPO/feeds/bundles/current/manifest.json" ]]; then
  sudo mkdir -p "$DEST/feeds/bundles"
  sudo rsync -aL --delete "$REPO/feeds/bundles/current/" "$DEST/feeds/bundles/current/"
fi
sudo find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
sudo chown -R root:root "$DEST"

echo "== 4/7 Python environment"
if [[ ! -x "$DEST/.venv/bin/python" ]]; then
  sudo python3 -m venv "$DEST/.venv"
  # Debian's bundled pip predates --uploaded-prior-to
  sudo env PIP_CONFIG_FILE=/dev/null "$DEST/.venv/bin/pip" install -q --index-url https://pypi.org/simple --upgrade pip
fi
sudo env PIP_CONFIG_FILE=/dev/null "$DEST/.venv/bin/pip" install -q --index-url https://pypi.org/simple \
  --uploaded-prior-to 2026-11-02T00:00:00Z -r "$DEST/requirements.txt"

echo "== 5/7 State directory, MAC vendor table, log rotation"
sudo install -d -o netwatch -g netwatch -m 0750 /var/lib/netwatch /var/lib/netwatch/sensor
[[ -s /var/lib/netwatch/manuf.tsv ]] || tshark -G manuf | sudo -u netwatch tee /var/lib/netwatch/manuf.tsv >/dev/null
sudo install -m 0644 "$REPO/setup/logrotate-netwatch" /etc/logrotate.d/netwatch
sudo install -d -m 0755 /etc/netwatch

echo "   Llama explainer"
LLM="$REPO/llm/artifacts"
# Use NETWATCH_MODEL if set, else our own export, else any prebuilt .pte (e.g. Meta's SpinQuant download).
MODEL="${NETWATCH_MODEL:-}"
if [[ -z "$MODEL" ]]; then
  if [[ -f "$LLM/llama3_2_1b_instruct_8da4w.pte" ]]; then MODEL=llama3_2_1b_instruct_8da4w.pte
  else MODEL="$(cd "$LLM" 2>/dev/null && ls -1 *.pte 2>/dev/null | head -n1 || true)"; fi
fi
if [[ -n "$MODEL" && -x "$LLM/llama_main" && -f "$LLM/libllama_runner.so" && -f "$LLM/$MODEL" && -f "$LLM/tokenizer.model" ]]; then
  sudo install -d -m 0755 "$DEST/llm"
  sudo install -m 0755 "$LLM/llama_main" "$LLM/libllama_runner.so" "$DEST/llm/"
  # Resident runner (keeps the model loaded between alerts); optional, llama_main is the fallback.
  if [[ -x "$LLM/netwatch_llm" ]]; then sudo install -m 0755 "$LLM/netwatch_llm" "$DEST/llm/"; fi
  sudo install -m 0644 "$LLM/$MODEL" "$LLM/tokenizer.model" "$DEST/llm/"
  sudo tee /etc/netwatch/netwatch.env >/dev/null <<EOF
# Written by setup/install_services.sh
NETWATCH_EXPLAINER=llama
NETWATCH_LLAMA_RUNNER=$DEST/llm/llama_main
NETWATCH_LLAMA_MODEL=$DEST/llm/$MODEL
NETWATCH_LLAMA_TOKENIZER=$DEST/llm/tokenizer.model
NETWATCH_LLAMA_THREADS=2
EOF
  echo "   OK: Llama ($MODEL) enabled"
else
  sudo rm -f /etc/netwatch/netwatch.env
  echo "   No runner/model in llm/artifacts yet: explanations use built-in templates"
fi

echo "== 6/7 Install and start services"
for u in "${UNITS[@]}"; do
  sudo install -m 0644 "$REPO/setup/systemd/$u.service" "/etc/systemd/system/$u.service"
done
sudo systemctl daemon-reload
sudo systemctl enable "${UNITS[@]/%/.service}"
sudo systemctl restart "${UNITS[@]/%/.service}"
echo "   waiting 20 s for the services to settle..."
sleep 20

echo "== 7/7 Verify"
ok=1
for u in "${UNITS[@]}"; do
  if systemctl is-active --quiet "$u"; then echo "OK: $u running"; else echo "!! $u not running" >&2; ok=0; fi
done
# The sensor's packet sockets must be bound to wlan0 only.
if sudo ss -0 -p 2>/dev/null | grep -i suricata | grep -q 'eth0'; then
  echo "!! sensor has a packet socket on eth0" >&2; ok=0
else
  echo "OK: sensor captures on wlan0 only"
fi
netsafety_eth0_not_promisc || ok=0
netsafety_new_listeners_ok "$SNAP/listeners.before" || ok=0
if ss -Htln 'sport = :8088' | grep -q '192.168.1.1:8088'; then echo "OK: dashboard on 192.168.1.1:8088"; else echo "!! dashboard not listening" >&2; ok=0; fi
netsafety_snapshot "$SNAP/after"
netsafety_diff "$SNAP/before" "$SNAP/after" || ok=0
for p in dnsmasq hostapd; do pgrep -x "$p" >/dev/null && echo "OK: $p still running" || { echo "!! $p not running" >&2; ok=0; }; done
ps -o rss=,comm= -u netwatch | awk '{s+=$1} END {printf "   NetWatch memory: %.0f MB\n", s/1024}'

[[ $ok == 1 ]] || rollback
cat <<EOF

NetWatch is live. Dashboard: http://192.168.1.1:8088 (from any device on the Wi-Fi).
Logs:    journalctl -u netwatch-sensor -u netwatch-live -u netwatch-web -f
Remove:  bash setup/uninstall_services.sh
EOF
