"""Suricata EVE JSON -> SQLite. Used for both live tailing and offline pcap replays."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .. import db
from ..config import Config
from ..devices import guess_kind, is_random_mac, vendor_for


def _ts(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _flags(hexstr: str | None) -> int:
    try:
        return int(hexstr, 16) if hexstr else 0
    except ValueError:
        return 0


def _src_mac(ev: dict) -> str | None:
    eth = ev.get("ether") or {}
    if eth.get("src_mac"):
        return eth["src_mac"]
    macs = eth.get("src_macs") or []
    return macs[0] if macs else None


def _dst_mac(ev: dict) -> str | None:
    eth = ev.get("ether") or {}
    if eth.get("dest_mac"):
        return eth["dest_mac"]
    macs = eth.get("dest_macs") or []
    return macs[0] if macs else None


class Ingestor:
    """Writes EVE events into the store and keeps the device inventory current."""

    def __init__(self, conn: sqlite3.Connection, cfg: Config):
        self.conn = conn
        self.cfg = cfg
        self.clock = db.get_meta(conn, "event_clock", 0.0) or 0.0
        self.hostnames: dict[str, str] = {}
        self.first_ts: float | None = None  # earliest event this ingestor has seen
        self.last_ts: float | None = None

    # -- devices -----------------------------------------------------------------

    def _is_client(self, ip: str | None) -> bool:
        return self.cfg.is_lan_host(ip) and ip != self.cfg.router_ip

    def _touch_device(self, ip: str, mac: str | None, ts: float, up: int = 0, down: int = 0, flows: int = 0) -> None:
        hostname = self.hostnames.get(ip)
        self.conn.execute(
            """INSERT INTO devices(ip, mac, mac_random, vendor, hostname, kind, first_seen, last_seen,
                                   bytes_up, bytes_down, flows)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET
                 mac=COALESCE(excluded.mac, devices.mac),
                 mac_random=CASE WHEN excluded.mac IS NOT NULL THEN excluded.mac_random ELSE devices.mac_random END,
                 vendor=COALESCE(excluded.vendor, devices.vendor),
                 hostname=COALESCE(excluded.hostname, devices.hostname),
                 kind=CASE WHEN excluded.kind != 'Unknown' THEN excluded.kind ELSE devices.kind END,
                 first_seen=MIN(devices.first_seen, excluded.first_seen),
                 last_seen=MAX(devices.last_seen, excluded.last_seen),
                 bytes_up=devices.bytes_up + excluded.bytes_up,
                 bytes_down=devices.bytes_down + excluded.bytes_down,
                 flows=devices.flows + excluded.flows""",
            (
                ip, mac, int(is_random_mac(mac)), vendor_for(mac), hostname,
                guess_kind(vendor_for(mac), hostname, is_random_mac(mac)),
                ts, ts, up, down, flows,
            ),
        )

    # -- events ------------------------------------------------------------------

    def handle(self, ev: dict) -> None:
        kind = ev.get("event_type")
        ts = _ts(ev.get("timestamp"))
        if ts is None:
            return
        if kind == "flow":
            start = _ts((ev.get("flow") or {}).get("start"))
            ts_lo = min(ts, start) if start else ts
        else:
            ts_lo = ts
        self.first_ts = ts_lo if self.first_ts is None else min(self.first_ts, ts_lo)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        handler = getattr(self, f"_on_{kind}", None)
        if handler:
            handler(ev, ts)

    def _on_flow(self, ev: dict, ts: float) -> None:
        f = ev.get("flow") or {}
        tcp = ev.get("tcp") or {}
        start = _ts(f.get("start")) or ts
        end = _ts(f.get("end")) or start
        src, dst = ev.get("src_ip"), ev.get("dest_ip")
        out_b, in_b = f.get("bytes_toserver", 0), f.get("bytes_toclient", 0)
        self.conn.execute(
            """INSERT INTO flows(ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, app_proto,
                                 pkts_out, pkts_in, bytes_out, bytes_in, state, flags_ts, flags_tc, community_id)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                start, end, src, ev.get("src_port"), dst, ev.get("dest_port"), ev.get("proto"),
                ev.get("app_proto"), f.get("pkts_toserver", 0), f.get("pkts_toclient", 0), out_b, in_b,
                f.get("state"), _flags(tcp.get("tcp_flags_ts")), _flags(tcp.get("tcp_flags_tc")),
                ev.get("community_id"),
            ),
        )
        if self._is_client(src):
            self._touch_device(src, _src_mac(ev), end, up=out_b, down=in_b, flows=1)
        if self._is_client(dst):
            self._touch_device(dst, _dst_mac(ev), end, up=in_b, down=out_b, flows=0 if self._is_client(src) else 1)
        self.clock = max(self.clock, end)

    def _on_dns(self, ev: dict, ts: float) -> None:
        d = ev.get("dns") or {}
        src = ev.get("src_ip")
        name = (d.get("rrname") or "").rstrip(".").lower()
        if d.get("type") == "query":
            self.conn.execute(
                "INSERT INTO dns(ts, src_ip, rrname, rrtype, rcode, answers) VALUES(?,?,?,?,?,?)",
                (ts, src, name, d.get("rrtype"), None, None),
            )
        elif d.get("type") == "answer":
            ips = [a["rdata"] for a in d.get("answers") or [] if a.get("rrtype") in ("A", "AAAA") and a.get("rdata")]
            # Fill in the answer on the matching query row (most recent from this client).
            self.conn.execute(
                """UPDATE dns SET rcode=?, answers=? WHERE id = (
                     SELECT id FROM dns WHERE src_ip=? AND rrname=? AND rcode IS NULL ORDER BY ts DESC LIMIT 1)""",
                (d.get("rcode"), json.dumps(ips), src, name),
            )
            for ip in ips:
                self.conn.execute(
                    """INSERT INTO resolutions(ip, domain, ts) VALUES(?,?,?)
                       ON CONFLICT(ip, domain) DO UPDATE SET ts=excluded.ts""",
                    (ip, name, ts),
                )
        if self._is_client(src):
            self._touch_device(src, _src_mac(ev), ts)
        self.clock = max(self.clock, ts)

    def _tls_row(self, ev: dict, ts: float, transport: str, t: dict) -> None:
        ja3 = t.get("ja3") or {}
        self.conn.execute(
            """INSERT INTO tls(ts, src_ip, dst_ip, dst_port, transport, sni, version, ja3, ja4, subject, issuer)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ts, ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"), transport,
                (t.get("sni") or "").rstrip(".").lower() or None, t.get("version"),
                ja3.get("hash") if isinstance(ja3, dict) else None, t.get("ja4"),
                t.get("subject"), t.get("issuerdn") or t.get("issuer"),
            ),
        )
        if self._is_client(ev.get("src_ip")):
            self._touch_device(ev["src_ip"], _src_mac(ev), ts)
        self.clock = max(self.clock, ts)

    def _on_tls(self, ev: dict, ts: float) -> None:
        self._tls_row(ev, ts, "tls", ev.get("tls") or {})

    def _on_quic(self, ev: dict, ts: float) -> None:
        q = ev.get("quic") or {}
        if q.get("sni"):
            self._tls_row(ev, ts, "quic", q)

    def _on_http(self, ev: dict, ts: float) -> None:
        h = ev.get("http") or {}
        self.conn.execute(
            """INSERT INTO http(ts, src_ip, dst_ip, dst_port, host, url, method, user_agent, status)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                ts, ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"),
                (h.get("hostname") or "").lower() or None, h.get("url"), h.get("http_method"),
                h.get("http_user_agent"), h.get("status"),
            ),
        )
        self.clock = max(self.clock, ts)

    def _on_dhcp(self, ev: dict, ts: float) -> None:
        d = ev.get("dhcp") or {}
        ip = d.get("assigned_ip") if d.get("assigned_ip") not in (None, "0.0.0.0") else d.get("client_ip")
        if d.get("hostname") and ip and ip != "0.0.0.0":
            self.hostnames[ip] = d["hostname"]
        if ip and self._is_client(ip):
            self._touch_device(ip, d.get("client_mac"), ts)

    # -- batch helpers -------------------------------------------------------------

    def feed(self, lines: Iterable[str]) -> int:
        n = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                self.handle(json.loads(line))
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
            n += 1
        db.set_meta(self.conn, "event_clock", self.clock)
        self.conn.commit()
        return n


def ingest_file(conn: sqlite3.Connection, cfg: Config, path: Path) -> Ingestor:
    ing = Ingestor(conn, cfg)
    with open(path, encoding="utf-8", errors="replace") as fh:
        ing.count = ing.feed(fh)
    return ing


class Tail:
    """Follows a growing eve.json, surviving rotation; remembers its position in the meta table."""

    def __init__(self, conn: sqlite3.Connection, cfg: Config, path: Path):
        self.ing = Ingestor(conn, cfg)
        self.conn = conn
        self.path = path
        state = db.get_meta(conn, "tail_state", {}) or {}
        self.inode = state.get("inode")
        self.offset = state.get("offset", 0)

    def poll(self, max_lines: int = 20000) -> int:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return 0
        if st.st_ino != self.inode or st.st_size < self.offset:
            self.inode, self.offset = st.st_ino, 0  # rotated or truncated
        lines = []
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            while len(lines) < max_lines:
                pos = fh.tell()
                raw = fh.readline()
                if not raw.endswith(b"\n"):
                    fh.seek(pos)  # EOF or partial line: pick it up next time
                    break
                lines.append(raw.decode("utf-8", "replace"))
            self.offset = fh.tell()
        n = self.ing.feed(lines)
        db.set_meta(self.conn, "tail_state", {"inode": self.inode, "offset": self.offset})
        self.conn.commit()
        return n
