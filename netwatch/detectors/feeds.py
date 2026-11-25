"""Threat-feed matching: every domain (DNS, TLS/QUIC SNI, HTTP Host) and external IP seen is
checked against the offline phishing / malware / C2 lists."""

from __future__ import annotations

import sqlite3

from ..alerts import AlertDraft
from ..config import Config
from ..feeds import FeedHit, get_index

SOURCE_LABEL = {"dns": "DNS lookup", "tls": "HTTPS (TLS SNI)", "quic": "HTTPS/3 (QUIC SNI)", "http": "HTTP Host header"}


class FeedDetector:
    name = "threat_feeds"

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def run(self, conn: sqlite3.Connection, cfg: Config, t0: float, t1: float) -> list[AlertDraft]:
        idx = get_index(cfg.feeds_dir, cfg.custom_feeds_dir)
        if not idx.domains and not idx.ips:
            return []
        # (device, indicator) -> collected sightings
        hits: dict[tuple, dict] = {}

        def record(device: str, hit: FeedHit, ts: float, source: str, observed: str) -> None:
            h = hits.setdefault((device, hit.indicator), {
                "hit": hit, "ts": [], "sources": set(), "observed": set(),
            })
            h["ts"].append(ts)
            h["sources"].add(source)
            h["observed"].add(observed)

        for r in conn.execute("SELECT ts, src_ip, rrname FROM dns WHERE ts >= ? AND ts < ?", (t0, t1)):
            if (hit := idx.match_domain(r["rrname"])):
                record(r["src_ip"], hit, r["ts"], "dns", r["rrname"])
        for r in conn.execute("SELECT ts, src_ip, sni, transport FROM tls WHERE ts >= ? AND ts < ? AND sni IS NOT NULL", (t0, t1)):
            if (hit := idx.match_domain(r["sni"])):
                record(r["src_ip"], hit, r["ts"], r["transport"], r["sni"])
        for r in conn.execute("SELECT ts, src_ip, host, url FROM http WHERE ts >= ? AND ts < ? AND host IS NOT NULL", (t0, t1)):
            if (hit := idx.match_domain(r["host"])):
                record(r["src_ip"], hit, r["ts"], "http", f"{r['host']}{r['url'] or ''}")
        if idx.ips:
            for r in conn.execute(
                "SELECT ts_start, src_ip, dst_ip, bytes_out, bytes_in FROM flows WHERE ts_start >= ? AND ts_start < ?", (t0, t1)
            ):
                for ip in (r["dst_ip"], r["src_ip"]):
                    if not cfg.is_lan(ip) and (hit := idx.match_ip(ip)):
                        device = r["src_ip"] if ip == r["dst_ip"] else r["dst_ip"]
                        record(device, hit, r["ts_start"], "ip", ip)

        alerts = []
        for (device, indicator), h in hits.items():
            alerts.append(self._draft(conn, cfg, device, indicator, h, t0, t1))
        return alerts

    def _draft(self, conn, cfg: Config, device: str, indicator: str, h: dict, t0: float, t1: float) -> AlertDraft:
        hit: FeedHit = h["hit"]
        sources = h["sources"]
        category = hit.category
        is_ip = "ip" in sources and len(sources) == 1

        # Did the device actually connect (not just look the name up)?
        connected_ips: list[str] = []
        if not is_ip:
            rows = conn.execute(
                """SELECT DISTINCT f.dst_ip FROM flows f JOIN resolutions r ON r.ip = f.dst_ip
                   WHERE f.src_ip = ? AND f.ts_start >= ? AND f.ts_start < ? AND (r.domain = ? OR r.domain LIKE ?)""",
                (device, t0, t1 + 60, indicator, f"%.{indicator}"),
            ).fetchall()
            connected_ips = [r["dst_ip"] for r in rows]
        connected = bool(connected_ips) or bool(sources & {"tls", "quic", "http", "ip"})

        if hit.confidence == "low":
            severity = "low"
        elif category in ("c2", "malware"):
            severity = "critical" if connected else "high"
        else:
            severity = "high" if connected else "medium"

        what = {
            "phishing": "phishing site", "scam": "scam site", "malware": "malware site",
            "c2": "malware command-and-control server", "lab": "lab test indicator",
        }.get(category, "known-bad site")
        verb = "connected to" if connected else "looked up"
        observed = sorted(h["observed"])
        title = f"{device} {verb} a listed {what}: {observed[0] if len(observed) == 1 else indicator}"
        resolved = [r["ip"] for r in conn.execute(
            "SELECT ip FROM resolutions WHERE domain = ? OR domain LIKE ? LIMIT 20", (indicator, f"%.{indicator}")
        )] if not is_ip else []

        return AlertDraft(
            detector=self.name, kind="c2_ip" if is_ip else f"{category}_domain", severity=severity, title=title,
            device_ip=device if cfg.is_lan(device) else None, peer=indicator,
            ts_first=min(h["ts"]), ts_last=max(h["ts"]),
            evidence={
                "indicator": indicator, "observed": observed[:20], "category": category,
                "confidence": hit.confidence, "exact_match": hit.exact,
                "seen_via": sorted(SOURCE_LABEL.get(s, "Connection to listed IP") for s in sources),
                "feeds": [{"name": f.name, "category": f.category, "fetched_at": f.fetched_at} for f in hit.feeds],
                "sightings": len(h["ts"]), "connected": connected,
                "connected_ips": connected_ips[:20], "resolved_ips": resolved,
                "notes": ["Listed host belongs to a shared platform; only part of it may be malicious"]
                if hit.confidence == "low" else [],
            },
        )


def feed_status(cfg: Config) -> dict:
    idx = get_index(cfg.feeds_dir, cfg.custom_feeds_dir)
    return {
        "built_at": idx.built_at,
        "domains": len(idx.domains), "ips": len(idx.ips),
        "feeds": [f.__dict__ for f in idx.feeds],
    }
