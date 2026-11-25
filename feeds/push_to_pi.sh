#!/usr/bin/env bash
# Copy the newest feed bundle from this laptop to the Pi over the Wi-Fi LAN and make it current.
#   bash feeds/push_to_pi.sh [user@192.168.1.1]
set -euo pipefail
PI="${1:-$USER@192.168.1.1}"
ROOT="$(cd "$(dirname "$0")" && pwd)/bundles"
STAMP="$(readlink "$ROOT/current")"
[[ -n "$STAMP" && -f "$ROOT/$STAMP/manifest.json" ]] || { echo "No bundle; run: python -m netwatch feeds-build" >&2; exit 1; }
ssh "$PI" "mkdir -p ~/netwatch/feeds/bundles"
scp -rq "$ROOT/$STAMP" "$PI:netwatch/feeds/bundles/"
ssh "$PI" "cd ~/netwatch/feeds/bundles && ln -sfn '$STAMP' current && ls -la current"
echo "Pushed $STAMP"
