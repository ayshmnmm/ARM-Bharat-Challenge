#!/usr/bin/env bash
# Stop and remove the NetWatch services. Keeps /var/lib/netwatch (data) unless --purge is given.
#   bash setup/uninstall_services.sh [--purge]
set -euo pipefail
if [[ $EUID -eq 0 ]]; then echo "Run as your normal user; the script calls sudo itself." >&2; exit 1; fi
UNITS=(netwatch-sensor netwatch-live netwatch-web)

sudo systemctl disable --now "${UNITS[@]/%/.service}" 2>/dev/null || true
for u in "${UNITS[@]}"; do sudo rm -f "/etc/systemd/system/$u.service"; done
sudo systemctl daemon-reload
sudo rm -f /etc/logrotate.d/netwatch
sudo rm -rf /opt/netwatch
if [[ "${1:-}" == "--purge" ]]; then
  sudo rm -rf /var/lib/netwatch /etc/netwatch
  id netwatch >/dev/null 2>&1 && sudo userdel netwatch
  echo "Removed services, code, data and the netwatch user."
else
  echo "Removed services and code. Data kept in /var/lib/netwatch (use --purge to delete)."
fi
