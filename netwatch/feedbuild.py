"""Build a threat-feed bundle. Run this on a laptop, NOT on the Pi (the Pi must not fetch from
the internet at runtime), then copy the bundle over with feeds/push_to_pi.sh.

    python -m netwatch feeds-build            # writes feeds/bundles/<UTC stamp>/ and points 'current' at it
    python -m netwatch feeds-build --from DIR # no network: parse <name>.txt files downloaded elsewhere
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .config import REPO, load
from .feeds import SHARED_PLATFORMS, is_ip, normalise_host, registrable

USER_AGENT = "NetWatch-feed-builder/0.1 (offline home IDS research project)"

# name, url, format, category
SOURCES = [
    ("openphish", "https://openphish.com/feed.txt", "urls", "phishing"),
    ("phishing_army", "https://phishing.army/download/phishing_army_blocklist.txt", "domains", "phishing"),
    # abuse.ch's own URLhaus/ThreatFox exports now need an account key; this is the keyless URLhaus mirror
    ("urlhaus", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", "hosts", "malware"),
    ("feodo_c2", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ips", "c2"),
]


def _running_on_router() -> bool:
    try:
        cfg = load()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((cfg.router_ip, 0))  # only succeeds if this machine owns the router's LAN address
        s.close()
        return True
    except OSError:
        return False


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse(text: str, fmt: str) -> tuple[set[str], set[str], int]:
    """Returns (domains, ips, dropped_shared)."""
    domains: set[str] = set()
    ips: set[str] = set()
    dropped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "!")):
            continue
        if fmt == "urls":
            host = normalise_host(urlsplit(line if "://" in line else f"http://{line}").hostname)
        elif fmt == "hosts":
            parts = line.split()
            host = normalise_host(parts[1] if len(parts) >= 2 else parts[0])
        elif fmt == "ips":
            token = line.split()[0].split(",")[0]
            try:
                ips.add(str(ipaddress.ip_address(token)))
            except ValueError:
                pass
            continue
        else:
            host = normalise_host(line.split()[0])
        if not host or host in ("localhost", "0.0.0.0", "127.0.0.1"):
            continue
        if is_ip(host):
            ips.add(host)
        elif registrable(host) in SHARED_PLATFORMS:
            dropped += 1  # a path on a shared service: matching the hostname would flag everyone
        else:
            domains.add(host)
    return domains, ips, dropped


def build(out_root: Path | None = None, raw_dir: Path | None = None) -> Path:
    """raw_dir: read <name>.txt from this folder instead of fetching (allowed on the router)."""
    if raw_dir is None and _running_on_router() and os.environ.get("NETWATCH_ALLOW_FEED_FETCH") != "1":
        raise SystemExit("Refusing to fetch feeds on the router (no outbound traffic from the Pi). "
                         "Run this on a laptop and push the bundle with feeds/push_to_pi.sh.")
    out_root = out_root or REPO / "feeds" / "bundles"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = out_root / stamp
    out.mkdir(parents=True)
    manifest = {"built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "feeds": []}
    for name, url, fmt, category in SOURCES:
        try:
            if raw_dir is not None:
                raw = raw_dir / f"{name}.txt"
                text = raw.read_text(encoding="utf-8", errors="replace")
                fetched = datetime.fromtimestamp(raw.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")
            else:
                text = _fetch(url)
                fetched = datetime.now(timezone.utc).isoformat(timespec="seconds")
        except Exception as e:  # one dead feed should not kill the bundle
            print(f"  ! {name}: {e}")
            continue
        domains, ips, dropped = parse(text, fmt)
        for kind, values in (("domain", domains), ("ip", ips)):
            if not values:
                continue
            fname = f"{name}.{kind}s.txt"
            body = "\n".join(sorted(values)) + "\n"
            (out / fname).write_text(body)
            manifest["feeds"].append({
                "name": name, "kind": kind, "category": category, "file": fname, "source": url,
                "fetched_at": fetched, "count": len(values), "sha256": hashlib.sha256(body.encode()).hexdigest(),
            })
        print(f"  {name}: {len(domains)} domains, {len(ips)} IPs, {dropped} shared-platform URLs dropped")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    current = out_root / "current"
    if current.is_symlink() or current.exists():
        current.unlink()
    current.symlink_to(stamp)
    print(f"Bundle: {out}")
    return out
