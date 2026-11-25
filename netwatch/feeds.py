"""Offline threat-feed index: domain and IP indicators from sideloaded feed bundles.

A bundle is a directory with manifest.json plus one text file per feed (one indicator per line).
Bundles are built on another machine (feeds/build_bundle.py) and copied to the Pi; nothing here
touches the network.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

import tldextract

# Offline public-suffix lookups only (bundled snapshot; never fetches).
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Services where the phishing page is a *path* on a shared hostname (docs.google.com/forms/...).
# HTTPS only reveals the hostname, so matching these hosts would flag every user of the service.
SHARED_PLATFORMS = {
    "google.com", "googleusercontent.com", "googleapis.com", "forms.gle", "goo.gl", "g.page",
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly",
    "dropbox.com", "dropboxusercontent.com", "live.com", "1drv.ms", "office.com", "microsoft.com",
    "sharepoint.com", "microsoftonline.com", "github.com", "githubusercontent.com", "gitlab.com",
    "ipfs.io", "cloudflare-ipfs.com", "dweb.link", "amazonaws.com", "cloudfront.net", "azureedge.net",
    "akamaized.net", "fastly.net", "linktr.ee", "t.me", "telegram.org", "wa.me", "whatsapp.com",
    "facebook.com", "instagram.com", "youtube.com", "canva.com", "notion.so", "wix.com",
    "apple.com", "icloud.com", "yahoo.com", "zoho.com", "mediafire.com", "wetransfer.com",
}


def registrable(host: str) -> str:
    r = _extract(host)
    rd = r.top_domain_under_public_suffix if hasattr(r, "top_domain_under_public_suffix") else r.registered_domain
    return rd or host


def normalise_host(host: str | None) -> str | None:
    if not host:
        return None
    host = host.strip().strip(".").lower()
    if host.count(":") == 1:
        host = host.split(":")[0]  # host:port
    return host or None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass
class Feed:
    name: str
    kind: str          # domain | ip
    category: str      # phishing | malware | c2 | scam | lab
    count: int = 0
    source: str = ""
    fetched_at: str | None = None


@dataclass
class FeedHit:
    indicator: str
    feeds: list[Feed]
    exact: bool
    confidence: str    # high | low

    @property
    def category(self) -> str:
        order = ["c2", "malware", "phishing", "scam", "lab"]
        cats = {f.category for f in self.feeds}
        return next((c for c in order if c in cats), self.feeds[0].category)


@dataclass
class FeedIndex:
    feeds: list[Feed] = field(default_factory=list)
    domains: dict[str, list[Feed]] = field(default_factory=dict)
    ips: dict[str, list[Feed]] = field(default_factory=dict)
    built_at: str | None = None

    def _add_file(self, feed: Feed, path: Path) -> None:
        n = 0
        table = self.ips if feed.kind == "ip" else self.domains
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key = line.lower() if feed.kind == "ip" else normalise_host(line)
            if key:
                table.setdefault(key, []).append(feed)
                n += 1
        feed.count = n
        self.feeds.append(feed)

    @classmethod
    def load(cls, bundle_dir: Path | None, custom_dir: Path | None) -> "FeedIndex":
        idx = cls()
        if bundle_dir and (bundle_dir / "manifest.json").exists():
            manifest = json.loads((bundle_dir / "manifest.json").read_text())
            idx.built_at = manifest.get("built_at")
            for f in manifest.get("feeds", []):
                path = bundle_dir / f["file"]
                if path.exists():
                    idx._add_file(Feed(f["name"], f["kind"], f["category"], source=f.get("source", ""),
                                       fetched_at=f.get("fetched_at")), path)
        if custom_dir and custom_dir.is_dir():
            for path in sorted(custom_dir.glob("*.txt")):
                hdr = {}
                for line in path.read_text(errors="replace").splitlines()[:10]:
                    if line.startswith("#") and ":" in line:
                        k, v = line[1:].split(":", 1)
                        hdr[k.strip().lower()] = v.strip()
                idx._add_file(Feed(hdr.get("name", path.stem), hdr.get("kind", "domain"),
                                   hdr.get("category", "phishing"), source="custom"), path)
        return idx

    def match_domain(self, host: str | None) -> FeedHit | None:
        host = normalise_host(host)
        if not host or is_ip(host):
            return None
        reg = registrable(host)
        candidate = host
        while True:
            feeds = self.domains.get(candidate)
            if feeds:
                conf = "low" if registrable(candidate) in SHARED_PLATFORMS else "high"
                return FeedHit(candidate, feeds, candidate == host, conf)
            if candidate == reg or "." not in candidate:
                return None
            candidate = candidate.split(".", 1)[1]

    def match_ip(self, ip: str | None) -> FeedHit | None:
        if not ip:
            return None
        feeds = self.ips.get(ip.lower())
        return FeedHit(ip, feeds, True, "high") if feeds else None


_cache: dict[tuple, FeedIndex] = {}


def get_index(bundle_dir: Path, custom_dir: Path) -> FeedIndex:
    """Cached index; reloaded when the bundle manifest or a custom list changes."""
    def mtime(p: Path) -> float:
        return p.stat().st_mtime if p.exists() else 0.0

    key = (
        str(bundle_dir), mtime(bundle_dir / "manifest.json"), str(bundle_dir.resolve()) if bundle_dir.exists() else "",
        tuple((p.name, mtime(p)) for p in sorted(custom_dir.glob("*.txt"))) if custom_dir.is_dir() else (),
    )
    if key not in _cache:
        _cache.clear()
        _cache[key] = FeedIndex.load(bundle_dir, custom_dir)
    return _cache[key]
