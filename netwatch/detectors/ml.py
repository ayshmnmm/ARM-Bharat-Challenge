"""M0 machine-learning detector.

Every TCP/UDP flow in the window is scored by the flow classifier (trained on CIC-IDS2017). One odd
flow proves nothing, so an alert needs many confident attack verdicts of the same family from one
source in the same window. If a rule-based alert already covers that device, the model's verdict is
attached to it as an independent second opinion instead of raising a duplicate.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict

import numpy as np

from ..alerts import AlertDraft
from ..config import Config
from ..ml.features import FEATURES, PLAIN

ML_MIN_PROB = 0.90       # per-flow confidence needed to count a flow as an attack
ML_MIN_FLOWS = 10        # distinct attack connections of one family from one source in one window
ML_HIGH_FLOWS = 50

FAMILY = {
    "dos": "denial of service (flooding a service)",
    "scan": "scanning (probing for open services)",
    "brute_force": "password guessing",
    "web_attack": "web attack (malicious requests to a website)",
    "botnet": "botnet traffic (a remotely controlled device)",
}
# Rule kinds that describe the same family, so a second opinion can say whether the two agree.
SAME_FAMILY = {"scan": {"port_scan", "host_sweep"}, "dos": {"syn_flood"}, "brute_force": {"brute_force"}}


def _device(cfg: Config, src: str, dst: str) -> str:
    if cfg.is_lan(src) and src != cfg.router_ip:
        return src
    if cfg.is_lan(dst):
        return dst
    return src


class MLDetector:
    name = "ml"

    def __init__(self, model):
        self.model = model
        self.importance = [f for f, _ in model.card.get("permutation_importance", [])] or FEATURES
        self.benign_median = model.card.get("benign_median", {})

    def run(self, conn: sqlite3.Connection, cfg: Config, t0: float, t1: float) -> list[AlertDraft]:
        rows = conn.execute(
            """SELECT ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in, bytes_out, bytes_in
               FROM flows WHERE ts_start >= ? AND ts_start < ? AND proto IN ('TCP', 'UDP')""",
            (t0, t1),
        ).fetchall()
        if not rows:
            return []
        X, idx, prob = self.model.score(rows)
        per_src = Counter(r["src_ip"] for r in {(r["src_ip"], r["dst_ip"], r["dst_port"], r["src_port"]): r
                                                  for r in rows}.values())
        groups: dict[tuple, list[int]] = defaultdict(list)
        for i, (c, p) in enumerate(zip(idx, prob)):
            cls = self.model.classes[c]
            if cls != "benign" and p >= ML_MIN_PROB:
                groups[(rows[i]["src_ip"], cls)].append(i)

        out = []
        for (src, cls), ids in groups.items():
            # Count distinct connections, not flow records: Suricata logs one long session (an open SSH
            # window, say) as many records with the same addresses and ports. Attacks open new ones.
            conns = {(rows[i]["dst_ip"], rows[i]["dst_port"], rows[i]["src_port"]) for i in ids}
            if len(conns) < ML_MIN_FLOWS:
                continue
            fl = [rows[i] for i in ids]
            targets = Counter(r["dst_ip"] for r in fl)
            ports = Counter(r["dst_port"] for r in fl)
            top_target = targets.most_common(1)[0][0]
            device = _device(cfg, src, top_target)
            conf = float(np.mean(prob[ids]))
            verdict = {
                "model": "gradient-boosted trees trained on CIC-IDS2017",
                "family": cls,
                "family_plain": FAMILY[cls],
                "flows_flagged": len(conns),
                "flows_from_source": per_src[src],
                "confidence": round(conf, 3),
                "source": src,
                "targets": [ip for ip, _ in targets.most_common(5)],
                "target_count": len(targets),
                "ports": [p for p, _ in ports.most_common(8)],
                "port_count": len(ports),
                "what_the_model_saw": self._signals(X[ids]),
            }
            t_first = min(r["ts_start"] for r in fl)
            t_last = max(r["ts_end"] for r in fl)
            if self._attach(conn, device, cls, verdict, t0, t1):
                continue
            out.append(AlertDraft(
                detector=self.name, kind=f"ml_{cls}",
                severity="high" if len(conns) >= ML_HIGH_FLOWS and conf >= 0.95 else "medium",
                title=f"AI model: traffic from {src} looks like {FAMILY[cls].split(' (')[0]}",
                device_ip=device, peer=top_target if device == src else src,
                ts_first=t_first, ts_last=t_last, evidence=verdict,
            ))
        return out

    def _signals(self, Xa: np.ndarray) -> list[dict]:
        """The most important features: typical value in the flagged flows vs ordinary traffic."""
        out = []
        for f in self.importance[:4]:
            i = FEATURES.index(f)
            out.append({
                "feature": f, "plain": PLAIN[f],
                "flagged_median": round(float(np.median(Xa[:, i])), 3),
                "normal_median": round(float(self.benign_median.get(f, 0.0)), 3),
            })
        return out

    def _attach(self, conn, device: str, cls: str, verdict: dict, t0: float, t1: float) -> bool:
        row = conn.execute(
            """SELECT id, kind, evidence FROM alerts
               WHERE detector != 'ml' AND device_ip IS ? AND status != 'resolved'
                 AND ts_last >= ? AND ts_first <= ? ORDER BY ts_last DESC LIMIT 1""",
            (device, t0 - 60, t1 + 60),
        ).fetchone()
        if not row:
            return False
        ev = json.loads(row["evidence"])
        verdict["agrees"] = row["kind"] in SAME_FAMILY.get(cls, set())
        first = "ml" not in ev
        prev = ev.get("ml") or {}
        if not first and prev.get("flows_flagged", 0) >= verdict["flows_flagged"]:
            return True
        ev["ml"] = verdict
        conn.execute("UPDATE alerts SET evidence=? WHERE id=?", (json.dumps(ev), row["id"]))
        if first:
            conn.execute("DELETE FROM explanations WHERE alert_id=?", (row["id"],))  # re-explain with both views
        return True
