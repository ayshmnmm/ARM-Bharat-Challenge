"""Device identification: MAC vendor (offline OUI table), randomised-MAC flag, kind guess."""

from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from pathlib import Path

from .config import load


def _manuf_path() -> Path:
    return load().home / "manuf.tsv"


@lru_cache(maxsize=1)
def _oui_table() -> dict[str, str]:
    """24-bit OUI -> vendor. Built once from Wireshark's bundled database (no network access)."""
    path = _manuf_path()
    if not path.exists():
        try:
            out = subprocess.run(["tshark", "-G", "manuf"], capture_output=True, text=True, timeout=60).stdout
            path.write_text(out)
        except (OSError, subprocess.SubprocessError):
            return {}
    table: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) >= 2 and len(parts[0]) == 8:  # plain 24-bit prefixes only
            table[parts[0].upper()] = parts[2] if len(parts) > 2 and parts[2] else parts[1]
    return table


def is_random_mac(mac: str | None) -> bool:
    """Locally administered bit set: phones use these for per-network private addresses."""
    if not mac or len(mac) < 2:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def vendor_for(mac: str | None) -> str | None:
    if not mac:
        return None
    if is_random_mac(mac):
        return "Private (randomised) MAC"
    return _oui_table().get(mac[:8].upper())


_KIND_RULES: list[tuple[str, str]] = [
    (r"raspberry", "Raspberry Pi"),
    (r"vmware|virtualbox|qemu|parallels", "Virtual machine"),
    (r"espressif|tuya|shenzhen|hikvision|dahua|ezviz|wyze|tp-?link.*(cam|plug)|sonoff", "IoT device"),
    (r"chromecast|roku|fire ?tv|sonos|lg ?electronics|samsung.*tv|bravia|android-?tv", "Media / TV"),
    (r"iphone|ipad|android|galaxy|pixel|oneplus|xiaomi|redmi|poco|oppo|vivo|realme|motorola|nothing", "Phone"),
    (r"desktop-|laptop-|windows|\bpc\b", "Windows PC"),
    (r"macbook|imac|mac-?mini", "Mac"),
    (r"intel corporate|azurewave|liteon|hon hai|chicony|realtek|mediatek|qualcomm", "Laptop / PC"),
    (r"apple", "Apple device"),
]


def guess_kind(vendor: str | None, hostname: str | None, mac_random: bool) -> str:
    text = f"{hostname or ''} {vendor or ''}".lower()
    for pattern, kind in _KIND_RULES:
        if re.search(pattern, text):
            return kind
    if mac_random:
        return "Phone / tablet (private MAC)"
    return "Unknown"
