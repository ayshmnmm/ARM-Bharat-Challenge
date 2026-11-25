#!/usr/bin/env bash
# Copy exported models + tokenizer from the export machine to the Pi over the Wi-Fi LAN.
#   bash llm/push_to_pi.sh [user@192.168.1.1]
set -euo pipefail
PI="${1:-$USER@192.168.1.1}"
SRC="${OUT:-$PWD/llm-out}"
ls "$SRC"/*.pte "$SRC/tokenizer.model" >/dev/null
ssh "$PI" "mkdir -p ~/netwatch/llm/artifacts"
scp "$SRC"/*.pte "$SRC/tokenizer.model" "$SRC/SHA256SUMS" "$PI:netwatch/llm/artifacts/"
ssh "$PI" "cd ~/netwatch/llm/artifacts && sha256sum -c SHA256SUMS --ignore-missing"
