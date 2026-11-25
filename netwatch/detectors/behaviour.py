"""M2 encrypted-threat detection from metadata only (NetWatch never decrypts anything):

- beaconing: a device contacting one internet address on a steady clock (malware check-ins)
- DGA: many look-ups of random, non-existent names (malware hunting for its control server)
- DNS tunnelling: data hidden in long, random DNS names under one domain
- new fingerprint: a TLS client fingerprint (JA4) never seen on that device or anywhere on the network
"""

from __future__ import annotations

import math
import sqlite3
import statistics
from collections import Counter, defaultdict

from ..alerts import AlertDraft
from ..config import Config
from ..feeds import is_ip, registrable

BEACON_LOOKBACK_S = 1800
BEACON_MIN_CONNS = 8
BEACON_MAX_JITTER = 0.15       # spread of the gaps / their average
BEACON_PERIOD_S = (10, 900)
BEACON_MAX_BYTES = 4000        # median bytes sent per check-in

DGA_MIN_NX = 10                # distinct non-existent names in one window
DGA_MIN_RANDOM_SHARE = 0.6

TUNNEL_MIN_NAMES = 20          # distinct names under one domain in one window
TUNNEL_MIN_LABEL = 25          # average length of the part before the domain

FINGERPRINT_LEARN_S = 86400    # learn a device's normal software for a day first

# Ports with naturally periodic traffic (time sync, DNS, mDNS, DHCP, SSDP).
_PERIODIC_OK = {53, 67, 68, 123, 137, 1900, 5353}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def looks_random(label: str) -> bool:
    """A domain label that reads like noise: long, high entropy, few vowels or digits mixed in."""
    if len(label) < 10:
        return False
    vowels = sum(ch in "aeiou" for ch in label) / len(label)
    digits = sum(ch.isdigit() for ch in label) / len(label)
    return entropy(label) >= 3.0 and (vowels < 0.3 or digits > 0.15)


def base_domain(name: str) -> str:
    reg = registrable(name)
    if reg == name and name.count(".") >= 2:  # unknown suffix (lab names): use the last two labels
        reg = ".".join(name.split(".")[-2:])
    return reg


class BehaviourDetector:
    name = "behaviour"

    def run(self, conn: sqlite3.Connection, cfg: Config, t0: float, t1: float) -> list[AlertDraft]:
        return (self._dga(conn, cfg, t0, t1) + self._tunnel(conn, cfg, t0, t1)
                + self._beacons(conn, cfg, t0, t1) + self._fingerprints(conn, cfg, t0, t1))

    # -- DGA --------------------------------------------------------------------------------

    def _dga(self, conn, cfg, t0, t1) -> list[AlertDraft]:
        nx: dict[str, set] = defaultdict(set)
        first: dict[str, float] = {}
        last: dict[str, float] = {}
        for r in conn.execute("SELECT ts, src_ip, rrname FROM dns WHERE ts >= ? AND ts < ? AND rcode = 'NXDOMAIN'",
                              (t0, t1)):
            nx[r["src_ip"]].add(r["rrname"].lower().rstrip("."))
            first.setdefault(r["src_ip"], r["ts"])
            last[r["src_ip"]] = r["ts"]
        out = []
        for src, names in nx.items():
            if len(names) < DGA_MIN_NX or not cfg.is_lan(src):
                continue
            rand = [n for n in names if looks_random(base_domain(n).split(".")[0])]
            share = len(rand) / len(names)
            if share < DGA_MIN_RANDOM_SHARE:
                continue
            out.append(AlertDraft(
                detector=self.name, kind="dga", severity="high",
                title=f"Possible malware: {src} looked up {len(names)} random, non-existent names",
                device_ip=src, peer=None, ts_first=first[src], ts_last=last[src],
                evidence={"source": src, "nxdomain_names": len(names), "random_looking": len(rand),
                          "random_share": round(share, 2), "sample_names": sorted(rand)[:10]},
            ))
        return out

    # -- DNS tunnelling ----------------------------------------------------------------------

    def _tunnel(self, conn, cfg, t0, t1) -> list[AlertDraft]:
        groups: dict[tuple, dict] = {}
        for r in conn.execute("SELECT ts, src_ip, rrname, rrtype FROM dns WHERE ts >= ? AND ts < ?", (t0, t1)):
            name = (r["rrname"] or "").lower().rstrip(".")
            base = base_domain(name)
            if not name.endswith(base) or name == base:
                continue
            g = groups.setdefault((r["src_ip"], base), {"names": set(), "types": Counter(), "ts": []})
            g["names"].add(name[: -len(base) - 1])
            g["types"][r["rrtype"]] += 1
            g["ts"].append(r["ts"])
        out = []
        for (src, base), g in groups.items():
            subs = g["names"]
            if len(subs) < TUNNEL_MIN_NAMES or not cfg.is_lan(src):
                continue
            avg_len = sum(len(s) for s in subs) / len(subs)
            avg_ent = sum(entropy(s.replace(".", "")) for s in subs) / len(subs)
            if avg_len < TUNNEL_MIN_LABEL or avg_ent < 3.5:
                continue
            out.append(AlertDraft(
                detector=self.name, kind="dns_tunnel", severity="high",
                title=f"Possible data hidden in DNS: {src} sent {len(subs)} long random names under {base}",
                device_ip=src, peer=base, ts_first=min(g["ts"]), ts_last=max(g["ts"]),
                evidence={"source": src, "domain": base, "distinct_names": len(subs),
                          "avg_name_length": round(avg_len, 1), "avg_entropy": round(avg_ent, 2),
                          "record_types": dict(g["types"]), "approx_bytes_encoded": int(sum(len(s) for s in subs) * 5 / 8),
                          "sample_names": sorted(subs)[:5]},
            ))
        return out

    # -- beaconing ---------------------------------------------------------------------------

    def _beacons(self, conn, cfg, t0, t1) -> list[AlertDraft]:
        pairs = conn.execute(
            """SELECT DISTINCT src_ip, dst_ip, dst_port FROM flows WHERE ts_start >= ? AND ts_start < ?
               AND proto = 'TCP'""", (t0, t1)).fetchall()
        out = []
        for p in pairs:
            src, dst, port = p["src_ip"], p["dst_ip"], p["dst_port"]
            if not cfg.is_lan(src) or cfg.is_lan(dst) or port in _PERIODIC_OK:
                continue
            records = conn.execute(
                """SELECT ts_start, ts_end, bytes_out, src_port FROM flows WHERE src_ip=? AND dst_ip=? AND dst_port=?
                   AND ts_start >= ? AND ts_start < ? ORDER BY ts_start""",
                (src, dst, port, t1 - BEACON_LOOKBACK_S, t1)).fetchall()
            # A check-in is a *new* connection. Suricata logs one long-lived connection (an app's keep-alive
            # to Google or Microsoft, say) as a record every time it goes quiet, which is just as regular.
            # Count each connection once, by its source port.
            rows = list({r["src_port"]: r for r in reversed(records)}.values())[::-1]
            if len(rows) < BEACON_MIN_CONNS:
                continue
            gaps = [b["ts_start"] - a["ts_start"] for a, b in zip(rows, rows[1:])]
            period = statistics.mean(gaps)
            if not BEACON_PERIOD_S[0] <= period <= BEACON_PERIOD_S[1]:
                continue
            jitter = statistics.pstdev(gaps) / period
            sent = statistics.median(r["bytes_out"] for r in rows)
            if jitter > BEACON_MAX_JITTER or sent > BEACON_MAX_BYTES:
                continue
            name = conn.execute("SELECT domain FROM resolutions WHERE ip=? ORDER BY ts DESC LIMIT 1", (dst,)).fetchone()
            sni = conn.execute("SELECT sni FROM tls WHERE dst_ip=? AND sni IS NOT NULL ORDER BY ts DESC LIMIT 1",
                               (dst,)).fetchone()
            out.append(AlertDraft(
                detector=self.name, kind="beaconing", severity="medium",
                title=f"Regular check-ins: {src} contacts {dst}:{port} every {period:.0f} s",
                device_ip=src, peer=dst, ts_first=rows[0]["ts_start"], ts_last=rows[-1]["ts_end"],
                evidence={"source": src, "destination": dst, "port": port,
                          "destination_name": (name and name["domain"]) or (sni and sni["sni"]),
                          "check_ins": len(rows), "period_s": round(period, 1), "jitter": round(jitter, 3),
                          "median_bytes_sent": int(sent), "watched_s": int(rows[-1]["ts_start"] - rows[0]["ts_start"])},
            ))
        return out

    # -- new TLS fingerprint -----------------------------------------------------------------

    def _fingerprints(self, conn, cfg, t0, t1) -> list[AlertDraft]:
        out = []
        for r in conn.execute(
            """SELECT src_ip, ja4, MIN(ts) AS ts, MAX(ts) AS ts_last, COUNT(*) AS n, GROUP_CONCAT(DISTINCT sni) AS snis
               FROM tls WHERE ts >= ? AND ts < ? AND ja4 IS NOT NULL GROUP BY src_ip, ja4""", (t0, t1)):
            src = r["src_ip"]
            dev = conn.execute("SELECT first_seen FROM devices WHERE ip=?", (src,)).fetchone()
            if not dev or not cfg.is_lan(src) or r["ts"] - dev["first_seen"] < FINGERPRINT_LEARN_S:
                continue  # still learning what this device normally runs
            seen_here = conn.execute("SELECT 1 FROM tls WHERE src_ip=? AND ja4=? AND ts < ? LIMIT 1",
                                     (src, r["ja4"], t0)).fetchone()
            if seen_here:
                continue
            others = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM tls WHERE ja4=? AND src_ip != ?",
                                  (r["ja4"], src)).fetchone()[0]
            if others:
                continue  # known software elsewhere on the network: an app install, not a stranger
            known = conn.execute("SELECT COUNT(DISTINCT ja4) FROM tls WHERE src_ip=? AND ts < ?", (src, t0)).fetchone()[0]
            out.append(AlertDraft(
                detector=self.name, kind="new_fingerprint", severity="low",
                title=f"New software on {src}: an encrypted-connection fingerprint never seen on this network",
                device_ip=src, peer=None, ts_first=r["ts"], ts_last=r["ts_last"],
                evidence={"source": src, "ja4": r["ja4"], "connections": r["n"],
                          "sites": sorted(set((r["snis"] or "").split(",")) - {""})[:5],
                          "fingerprints_known_for_device": known},
            ))
        return out


__all__ = ["BehaviourDetector", "entropy", "looks_random", "is_ip"]
