"""Alert model and storage. Repeated detections of the same thing merge into one alert."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# A new detection merges into an open alert with the same (kind, device, peer)
# if it starts within this many seconds of that alert's last activity.
MERGE_GAP_S = 900


@dataclass
class AlertDraft:
    detector: str
    kind: str
    severity: str
    title: str
    device_ip: str | None
    peer: str | None
    ts_first: float
    ts_last: float
    evidence: dict = field(default_factory=dict)


def upsert(conn: sqlite3.Connection, a: AlertDraft) -> int:
    row = conn.execute(
        """SELECT id, severity, ts_first, ts_last, evidence FROM alerts
           WHERE kind=? AND device_ip IS ? AND peer IS ? AND status != 'resolved' AND ts_last >= ?
           ORDER BY ts_last DESC LIMIT 1""",
        (a.kind, a.device_ip, a.peer, a.ts_first - MERGE_GAP_S),
    ).fetchone()
    if row:
        # Keep the evidence of the strongest detection; extend the time range.
        stronger = SEVERITY_RANK[a.severity] >= SEVERITY_RANK[row["severity"]]
        old = json.loads(row["evidence"])
        if "technique" in a.evidence and "technique" in old:
            seen = sorted(set(old.get("techniques_seen", [old["technique"]])) | {a.evidence["technique"]})
            if not stronger:
                old["techniques_seen"] = seen
                conn.execute("UPDATE alerts SET evidence=? WHERE id=?", (json.dumps(old), row["id"]))
            a.evidence["techniques_seen"] = seen
        # Overlapping detection windows re-report the same activity; only a new burst
        # (starting after the previous one ended) counts as another occurrence.
        if "ml" in old and "ml" not in a.evidence:
            a.evidence["ml"] = old["ml"]  # keep the model's second opinion when rule evidence is replaced
        new_burst = int(a.ts_first > row["ts_last"])
        # A new burst or a higher severity brings the alert back to the top of the list.
        reraise = bool(new_burst) or SEVERITY_RANK[a.severity] > SEVERITY_RANK[row["severity"]]
        conn.execute(
            f"""UPDATE alerts SET ts_first=MIN(ts_first, ?), ts_last=MAX(ts_last, ?), count=count+{new_burst},
                 severity=CASE WHEN ? THEN ? ELSE severity END,
                 title=CASE WHEN ? THEN ? ELSE title END,
                 evidence=CASE WHEN ? THEN ? ELSE evidence END,
                 ts_raised=CASE WHEN ? THEN ? ELSE ts_raised END
               WHERE id=?""",
            (a.ts_first, a.ts_last, stronger, a.severity, stronger, a.title, stronger,
             json.dumps(a.evidence), reraise, time.time(), row["id"]),
        )
        if stronger and a.severity != row["severity"]:
            conn.execute("DELETE FROM explanations WHERE alert_id=?", (row["id"],))  # re-explain
        return row["id"]
    cur = conn.execute(
        """INSERT INTO alerts(dedup_key, detector, kind, severity, title, device_ip, peer, ts_first, ts_last, evidence,
                              ts_raised)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            f"{a.kind}|{a.device_ip}|{a.peer}|{a.ts_first:.3f}", a.detector, a.kind, a.severity, a.title,
            a.device_ip, a.peer, a.ts_first, a.ts_last, json.dumps(a.evidence), time.time(),
        ),
    )
    return cur.lastrowid


def row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["evidence"] = json.loads(d["evidence"]) if d.get("evidence") else {}
    return d
