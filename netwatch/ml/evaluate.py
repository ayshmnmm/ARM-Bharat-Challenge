"""Cross-dataset check: does the model trained on CIC-IDS2017 work on traffic from *this* network?

  python -m netwatch ml-eval

Replays each capture through Suricata into a throwaway database, then reports, per capture, the
rule alerts, the ML alerts and second opinions, and the share of flows the model calls an attack.
Results are written into the model card ("lab_eval") so the dashboard and report show them.
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from dataclasses import replace
from pathlib import Path

from .. import db
from ..config import REPO, load

# (capture, what it contains, the attack family we expect, or None for ordinary traffic)
CAPTURES = [
    ("captures/try.pcapng", "6 min of real household Wi-Fi traffic", None),
    ("captures/nmap_scan.pcapng", "real nmap scans of the router", "scan"),
    ("tests/fixtures/lab_host_sweep.pcap", "synthetic host sweep", "scan"),
    ("tests/fixtures/lab_syn_flood.pcap", "synthetic SYN flood", "dos"),
    ("tests/fixtures/lab_ssh_bruteforce.pcap", "synthetic SSH password guessing", "brute_force"),
    ("tests/fixtures/lab_phishing_visit.pcap", "synthetic phishing visit", None),
    ("tests/fixtures/lab_lateral_probe.pcap", "synthetic worm-style probing of 3 devices (below every rule)", "scan"),
]


def evaluate(write_card: bool = True) -> list[dict]:
    from ..detectors import run_range  # noqa: F401  (imported for side effects in replay)
    from ..pipeline import replay
    from .model import get_model

    base = load()
    model = get_model(base.ml_dir)
    if model is None:
        raise SystemExit("no model: run `python -m netwatch ml-train` first")
    results = []
    for rel, what, expect in CAPTURES:
        pcap = REPO / rel
        if not pcap.exists():
            continue
        with tempfile.TemporaryDirectory(prefix="netwatch-eval-") as tmp:
            cfg = replace(base, home=Path(tmp), explainer="template")
            conn = db.connect(cfg.db_path)
            replay(conn, cfg, pcap, explain=False)
            rows = conn.execute(
                """SELECT ts_start, ts_end, src_ip, dst_ip, dst_port, proto, pkts_out, pkts_in, bytes_out, bytes_in
                   FROM flows WHERE proto IN ('TCP','UDP')""").fetchall()
            _, idx, prob = model.score(rows)
            verdicts = Counter(model.classes[i] if p >= 0.9 or model.classes[i] == "benign" else "benign (low confidence)"
                               for i, p in zip(idx, prob))
            alerts = [dict(r) for r in conn.execute("SELECT kind, detector, severity, evidence FROM alerts")]
            conn.close()
        rule = sorted({a["kind"] for a in alerts if a["detector"] != "ml"})
        ml_alerts = sorted({a["kind"] for a in alerts if a["detector"] == "ml"})
        confirmed = [json.loads(a["evidence"])["ml"] for a in alerts
                     if a["detector"] != "ml" and '"ml"' in a["evidence"]]
        flagged = sum(n for k, n in verdicts.items() if not k.startswith("benign"))
        found = {m["family"] for m in confirmed} | {k[3:] for k in ml_alerts}
        results.append({
            "capture": Path(rel).name, "contains": what, "expected": expect or "nothing",
            "flows": len(rows), "flows_flagged_by_ml": flagged,
            "flagged_share": round(flagged / len(rows), 4) if rows else 0.0,
            "ml_verdicts": dict(verdicts.most_common()),
            "rule_alerts": rule, "ml_alerts": ml_alerts,
            "ml_second_opinions": [{"family": m["family"], "flows": m["flows_flagged"], "agrees": m.get("agrees")}
                                   for m in confirmed],
            "ml_detected_expected": (expect in found) if expect else None,
            "ml_false_alarm": bool(ml_alerts) if expect is None else None,
        })
        print(json.dumps(results[-1]))
    if write_card:
        card_path = base.ml_dir / "flow_classifier.json"
        card = json.loads(card_path.read_text())
        card["lab_eval"] = results
        card_path.write_text(json.dumps(card, indent=2) + "\n")
    return results
