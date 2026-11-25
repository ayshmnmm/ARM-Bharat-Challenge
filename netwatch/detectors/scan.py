"""M0 core intrusion detection over flow records: port scans, host sweeps, SYN floods, login brute force."""

from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict

from ..alerts import AlertDraft
from ..config import Config

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

PORT_SCAN_MIN_PORTS = 15
PORT_SCAN_HIGH_PORTS = 100
SWEEP_MIN_HOSTS = 10
FLOOD_MIN_SYNS = 200
FLOOD_PORT_SHARE = 0.8         # share of the half-open connections that go to the 3 busiest ports
BRUTE_MIN_CONNS = 8
BRUTE_HIGH_CONNS = 30

AUTH_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 8080: "HTTP admin", 8443: "HTTPS admin",
}


def _is_probe(f: sqlite3.Row) -> bool:
    """A connection attempt that never carried data: SYN-only, refused, or handshake-then-reset."""
    if f["proto"] == "TCP":
        if f["flags_ts"] == SYN:   # only SYNs ever sent: Windows retries a refused port up to 4 times
            return f["pkts_out"] <= 8
        return bool(f["flags_ts"] & SYN) and f["pkts_out"] <= 3 and f["bytes_out"] <= 320
    if f["proto"] == "UDP":
        return f["pkts_out"] <= 2 and f["pkts_in"] == 0
    return False


def _is_open(f: sqlite3.Row) -> bool:
    return f["proto"] == "TCP" and (f["flags_tc"] & (SYN | ACK)) == (SYN | ACK)


class ScanDetector:
    name = "intrusion"

    def _device(self, cfg: Config, src: str, dst: str) -> str:
        """The LAN device an alert is about: the inside attacker if there is one, else the victim."""
        if cfg.is_lan(src) and src != cfg.router_ip:
            return src
        if cfg.is_lan(dst):
            return dst
        return src

    def _label(self, cfg: Config, ip: str) -> str:
        return f"{ip} (this router)" if ip == cfg.router_ip else ip

    def run(self, conn: sqlite3.Connection, cfg: Config, t0: float, t1: float) -> list[AlertDraft]:
        flows = conn.execute(
            """SELECT ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in,
                      bytes_out, bytes_in, flags_ts, flags_tc
               FROM flows WHERE ts_start >= ? AND ts_start < ?""",
            (t0, t1),
        ).fetchall()
        out: list[AlertDraft] = []
        out += self._port_scans(cfg, flows)
        out += self._sweeps(cfg, flows)
        out += self._floods(cfg, flows)
        out += self._brute_force(cfg, flows)
        return out

    # -- port scan: one source probing many ports on one host --------------------------

    def _port_scans(self, cfg: Config, flows) -> list[AlertDraft]:
        groups: dict[tuple, list] = defaultdict(list)
        for f in flows:
            if _is_probe(f) or (_is_open(f) and f["pkts_out"] <= 4):
                groups[(f["src_ip"], f["dst_ip"], f["proto"])].append(f)
        alerts = []
        for (src, dst, proto), group in groups.items():
            for fl in self._split_instances(group):
                if (a := self._port_scan_alert(cfg, src, dst, proto, fl)):
                    alerts.append(a)
        return alerts

    @staticmethod
    def _split_instances(fl: list) -> list[list]:
        """Separate scans that overlap in time. Crafted-packet scanners (nmap -sS) reuse one source
        port for every probe; OS-socket scans (nmap -sT) use a new ephemeral port per probe."""
        by_sport: dict[int, list] = defaultdict(list)
        for f in fl:
            by_sport[f["src_port"]].append(f)
        crafted = [g for g in by_sport.values() if len({f["dst_port"] for f in g}) >= PORT_SCAN_MIN_PORTS]
        crafted_ids = {id(f) for g in crafted for f in g}
        rest = [f for f in fl if id(f) not in crafted_ids]
        return crafted + ([rest] if rest else [])

    def _port_scan_alert(self, cfg: Config, src: str, dst: str, proto: str, fl: list) -> AlertDraft | None:
        ports = {f["dst_port"] for f in fl}
        if len(ports) < PORT_SCAN_MIN_PORTS:
            return None
        open_ports = sorted({f["dst_port"] for f in fl if _is_open(f)})
        src_ports = {f["src_port"] for f in fl}
        t_first = min(f["ts_start"] for f in fl)
        t_last = max(f["ts_end"] for f in fl)
        span = max(t_last - t_first, 0.001)
        completed = any(f["flags_ts"] & ACK for f in fl if _is_open(f))
        crafted = len(src_ports) <= 3
        if proto == "UDP":
            technique = "UDP scan"
        elif completed:
            technique = "TCP connect scan"
        else:
            technique = "SYN (half-open) scan"
        device = self._device(cfg, src, dst)
        return AlertDraft(
            detector=self.name, kind="port_scan",
            severity="high" if len(ports) >= PORT_SCAN_HIGH_PORTS else "medium",
            title=f"Port scan: {src} probed {len(ports)} {proto} ports on {self._label(cfg, dst)}",
            device_ip=device, peer=dst if device == src else src,
            ts_first=t_first, ts_last=t_last,
            evidence={
                "source": src, "target": dst, "protocol": proto, "technique": technique,
                "ports_probed": len(ports), "open_ports": open_ports[:50],
                "sample_ports": sorted(ports)[:25], "probes_per_second": round(len(fl) / span, 1),
                "duration_s": round(span, 2), "distinct_source_ports": len(src_ports),
                "crafted_packets": crafted,
                "notes": ["Same source port reused for every probe: typical of nmap-style tools"] if crafted else [],
            },
        )

    # -- host sweep: one source probing many LAN hosts -----------------------------------

    def _sweeps(self, cfg: Config, flows) -> list[AlertDraft]:
        groups: dict[str, list] = defaultdict(list)
        for f in flows:
            if cfg.is_lan(f["dst_ip"]) and (_is_probe(f) or f["proto"] == "ICMP"):
                groups[f["src_ip"]].append(f)
        alerts = []
        for src, fl in groups.items():
            hosts = {f["dst_ip"] for f in fl}
            if len(hosts) < SWEEP_MIN_HOSTS:
                continue
            alerts.append(AlertDraft(
                detector=self.name, kind="host_sweep", severity="medium",
                title=f"Network sweep: {src} probed {len(hosts)} devices on the network",
                device_ip=src if cfg.is_lan(src) else None, peer=None,
                ts_first=min(f["ts_start"] for f in fl), ts_last=max(f["ts_end"] for f in fl),
                evidence={
                    "source": src, "hosts_probed": len(hosts), "sample_hosts": sorted(hosts)[:25],
                    "protocols": sorted({f["proto"] for f in fl}),
                    "ports": sorted({f["dst_port"] for f in fl if f["dst_port"]})[:25],
                },
            ))
        return alerts

    # -- SYN flood: many unanswered SYNs at one service -----------------------------------

    def _floods(self, cfg: Config, flows) -> list[AlertDraft]:
        groups: dict[str, list] = defaultdict(list)
        for f in flows:
            if f["proto"] == "TCP" and f["flags_ts"] & SYN and not f["flags_ts"] & ACK and f["pkts_out"] <= 2:
                groups[f["dst_ip"]].append(f)
        alerts = []
        for dst, fl in groups.items():
            # A flood hammers a few ports; a scan spreads over many (handled above). Judge by the 3 busiest
            # ports, so a few unrelated probes of the same device in the same minute cannot hide a flood.
            top = Counter(f["dst_port"] for f in fl).most_common(3)
            busiest = {p for p, n in top if n * 10 >= top[0][1]}
            hammered = [f for f in fl if f["dst_port"] in busiest]
            if len(hammered) < FLOOD_MIN_SYNS or len(hammered) < FLOOD_PORT_SHARE * len(fl):
                continue
            fl, ports = hammered, busiest
            sources = {f["src_ip"] for f in fl}
            t_first, t_last = min(f["ts_start"] for f in fl), max(f["ts_end"] for f in fl)
            src_label = next(iter(sources)) if len(sources) == 1 else f"{len(sources)} sources"
            device = self._device(cfg, next(iter(sources)), dst) if len(sources) == 1 else dst
            alerts.append(AlertDraft(
                detector=self.name, kind="syn_flood", severity="high",
                title=f"SYN flood: {len(fl)} half-open connections to {self._label(cfg, dst)} port "
                      f"{', '.join(map(str, sorted(ports)))} from {src_label}",
                device_ip=device, peer=dst if device != dst else (None if len(sources) > 1 else next(iter(sources))),
                ts_first=t_first, ts_last=t_last,
                evidence={
                    "target": dst, "ports": sorted(ports), "syn_count": len(fl),
                    "distinct_sources": len(sources), "sample_sources": sorted(sources)[:10],
                    "syns_per_second": round(len(fl) / max(t_last - t_first, 0.001), 1),
                    "answered": sum(1 for f in fl if f["pkts_in"] > 0),
                },
            ))
        return alerts

    # -- brute force: repeated full logins against an authentication service ---------------

    def _brute_force(self, cfg: Config, flows) -> list[AlertDraft]:
        groups: dict[tuple, list] = defaultdict(list)
        for f in flows:
            if f["proto"] == "TCP" and f["dst_port"] in AUTH_PORTS and _is_open(f) and f["bytes_out"] > 300:
                groups[(f["src_ip"], f["dst_ip"], f["dst_port"])].append(f)
        alerts = []
        for (src, dst, port), fl in groups.items():
            if len(fl) < BRUTE_MIN_CONNS:
                continue
            service = AUTH_PORTS[port]
            alerts.append(AlertDraft(
                detector=self.name, kind="brute_force",
                severity="high" if len(fl) >= BRUTE_HIGH_CONNS else "medium",
                title=f"Possible {service} password guessing: {len(fl)} logins from {src} to {self._label(cfg, dst)}",
                device_ip=self._device(cfg, src, dst), peer=dst if self._device(cfg, src, dst) == src else src,
                ts_first=min(f["ts_start"] for f in fl), ts_last=max(f["ts_end"] for f in fl),
                evidence={
                    "source": src, "target": dst, "port": port, "service": service,
                    "connections": len(fl),
                    "avg_duration_s": round(sum(f["ts_end"] - f["ts_start"] for f in fl) / len(fl), 2),
                    "avg_bytes_sent": int(sum(f["bytes_out"] for f in fl) / len(fl)),
                },
            ))
        return alerts
