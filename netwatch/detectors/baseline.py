"""M1 per-device behaviour baselines: each device's own normal, learned on the Pi.

For every Wi-Fi device and every minute it is active, NetWatch tracks how much it uploads, how many
internet addresses it talks to and how many different services (ports) it uses. Running mean and
spread are kept per device (Welford's method, a few numbers per device, nothing else stored). After
a learning period, a minute far outside that device's own normal raises an alert: a camera that
suddenly uploads gigabytes, or a TV that starts talking to hundreds of addresses.
"""

from __future__ import annotations

import math
import sqlite3

from ..alerts import AlertDraft
from ..config import Config

LEARN_MINUTES = 120        # active minutes before a device's baseline is trusted
Z_ALERT = 6.0              # how many spreads above normal
# Absolute floors, so a quiet device going slightly less quiet never alerts.
FLOORS = {"upload_bytes": 50_000_000, "destinations": 40, "ports": 25}
METRIC_KIND = {"upload_bytes": "unusual_upload", "destinations": "unusual_destinations", "ports": "unusual_destinations"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_baseline (
    ip TEXT, metric TEXT, n INTEGER, mean REAL, m2 REAL, max REAL, last_t0 REAL,
    PRIMARY KEY (ip, metric)
);
"""


def _stats(row) -> tuple[int, float, float]:
    n, mean, m2 = row["n"], row["mean"], row["m2"]
    return n, mean, math.sqrt(m2 / (n - 1)) if n > 1 else 0.0


class BaselineDetector:
    name = "baseline"

    def run(self, conn: sqlite3.Connection, cfg: Config, t0: float, t1: float) -> list[AlertDraft]:
        if int(t0) % 60:
            return []  # windows overlap by half; learn from every other one so minutes are not counted twice
        conn.executescript(SCHEMA)
        rows = conn.execute(
            """SELECT src_ip, SUM(bytes_out) AS up, COUNT(DISTINCT dst_ip) AS dsts, COUNT(DISTINCT dst_port) AS ports,
                      MIN(ts_start) AS a, MAX(ts_end) AS b
               FROM flows WHERE ts_start >= ? AND ts_start < ? GROUP BY src_ip""", (t0, t1)).fetchall()
        out = []
        for r in rows:
            ip = r["src_ip"]
            if not cfg.is_lan_host(ip) or ip == cfg.router_ip:
                continue
            values = {"upload_bytes": r["up"] or 0, "destinations": r["dsts"], "ports": r["ports"]}
            for metric, v in values.items():
                row = conn.execute("SELECT * FROM device_baseline WHERE ip=? AND metric=?", (ip, metric)).fetchone()
                if row and row["last_t0"] is not None and t0 <= row["last_t0"]:
                    continue  # already learned from this minute (replays, late flows)
                if row and row["n"] >= LEARN_MINUTES:
                    n, mean, sd = _stats(row)
                    z = (v - mean) / max(sd, mean * 0.1, 1.0)
                    if z >= Z_ALERT and v >= FLOORS[metric]:
                        out.append(self._draft(ip, metric, v, mean, sd, n, z, r))
                        v = mean + Z_ALERT * sd  # learn from the event, capped, so one attack does not become normal
                self._update(conn, ip, metric, float(v), t0, row)
        return out

    @staticmethod
    def _update(conn, ip, metric, v, t0, row) -> None:
        if row is None:
            conn.execute("INSERT INTO device_baseline VALUES(?,?,?,?,?,?,?)", (ip, metric, 1, v, 0.0, v, t0))
            return
        n = row["n"] + 1
        delta = v - row["mean"]
        mean = row["mean"] + delta / n
        m2 = row["m2"] + delta * (v - mean)
        conn.execute("UPDATE device_baseline SET n=?, mean=?, m2=?, max=?, last_t0=? WHERE ip=? AND metric=?",
                     (n, mean, m2, max(row["max"], v), t0, ip, metric))

    def _draft(self, ip, metric, v, mean, sd, n, z, r) -> AlertDraft:
        kind = METRIC_KIND[metric]
        what = {"upload_bytes": "uploaded far more than usual", "destinations": "talked to far more addresses than usual",
                "ports": "used far more services than usual"}[metric]
        return AlertDraft(
            detector=self.name, kind=kind, severity="medium" if metric == "upload_bytes" else "low",
            title=f"Unusual for this device: {ip} {what}",
            device_ip=ip, peer=None, ts_first=r["a"], ts_last=r["b"],
            evidence={"source": ip, "metric": metric, "this_minute": int(v), "usual_per_minute": round(mean, 1),
                      "usual_spread": round(sd, 1), "times_above_usual": round(v / max(mean, 1), 1),
                      "minutes_learned": n, "z_score": round(z, 1)},
        )
