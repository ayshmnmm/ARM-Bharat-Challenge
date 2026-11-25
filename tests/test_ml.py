"""ML detector: feature mapping, alerting thresholds, second opinions, and the shipped model card."""

from __future__ import annotations

import json

import numpy as np
import pytest

from netwatch import db
from netwatch.alerts import AlertDraft, row_to_dict, upsert
from netwatch.config import REPO
from netwatch.criteria import criteria
from netwatch.detectors.ml import ML_MIN_FLOWS, MLDetector
from netwatch.explain.facts import facts, headline
from netwatch.ml import load_card
from netwatch.ml.features import FEATURES, from_flows


class StubModel:
    """Calls every flow to port 9999 a scan at 97%, everything else benign."""
    classes = ["benign", "dos", "scan", "brute_force", "botnet"]
    card = {"permutation_importance": [["dst_port", 0.4], ["fwd_payload", 0.2], ["fwd_pkts", 0.1]],
            "benign_median": {f: 1.0 for f in FEATURES}}

    def score(self, rows):
        X = from_flows(rows)
        idx = np.array([2 if r["dst_port"] == 9999 else 0 for r in rows])
        return X, idx, np.full(len(rows), 0.97)


def _flow(conn, ts, src="192.168.1.60", dst="192.168.1.1", port=9999, sport=None):
    conn.execute(
        """INSERT INTO flows(ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in,
                             bytes_out, bytes_in, flags_ts, flags_tc) VALUES(?,?,?,?,?,?,'TCP',1,1,74,60,2,20)""",
        (ts, ts + 0.001, src, sport if sport is not None else 40000 + int(ts), dst, port))


def test_suricata_bytes_become_cic_style_payload():
    row = {"dst_port": 443, "ts_start": 0.0, "ts_end": 2.0, "proto": "TCP", "pkts_out": 10, "pkts_in": 8,
           "bytes_out": 10 * 66 + 500, "bytes_in": 8 * 66 + 8000}
    x = dict(zip(FEATURES, from_flows([row])[0]))
    assert x["fwd_payload"] == 500 and x["bwd_payload"] == 8000  # headers removed, as CICFlowMeter counts
    assert x["fwd_mean"] == 50 and x["bwd_fwd_ratio"] == pytest.approx(0.8)
    assert not {"duration_s", "bytes_per_s", "pkts_per_s"} & set(FEATURES)   # timing depends on the network


def test_needs_many_confident_flows_before_alerting(cfg):
    conn = db.connect(cfg.db_path)
    for i in range(ML_MIN_FLOWS - 1):
        _flow(conn, 100 + i)
    det = MLDetector(StubModel())
    assert det.run(conn, cfg, 90, 150) == []
    _flow(conn, 120)
    (a,) = det.run(conn, cfg, 90, 150)
    assert a.kind == "ml_scan" and a.detector == "ml" and a.device_ip == "192.168.1.60"
    assert a.evidence["flows_flagged"] == ML_MIN_FLOWS and a.evidence["confidence"] == 0.97


def test_one_long_session_split_into_records_is_not_an_attack(cfg):
    conn = db.connect(cfg.db_path)
    for i in range(30):  # same addresses and ports: one SSH window logged in pieces
        _flow(conn, 100 + i, sport=51000)
    assert MLDetector(StubModel()).run(conn, cfg, 90, 150) == []


def test_verdict_is_attached_to_a_matching_rule_alert(cfg):
    conn = db.connect(cfg.db_path)
    for i in range(20):
        _flow(conn, 100 + i)
    upsert(conn, AlertDraft("intrusion", "port_scan", "medium", "Port scan", "192.168.1.60", "192.168.1.1",
                            100, 120, {"source": "192.168.1.60", "target": "192.168.1.1", "ports_probed": 20,
                                       "duration_s": 20, "technique": "SYN (half-open) scan"}))
    assert MLDetector(StubModel()).run(conn, cfg, 90, 150) == []  # no duplicate alert
    alert = row_to_dict(conn.execute("SELECT * FROM alerts").fetchone())
    assert alert["evidence"]["ml"]["agrees"] is True
    checks = [c["check"] for c in criteria(alert)]
    assert any("Independent AI detector" in c for c in checks)
    assert any("judged 20 connections" in f and "agreeing" in f for f in facts(alert))


def test_ml_alert_is_explained_from_facts(cfg):
    conn = db.connect(cfg.db_path)
    for i in range(12):
        _flow(conn, 100 + i)
    (draft,) = MLDetector(StubModel()).run(conn, cfg, 90, 150)
    upsert(conn, draft)
    alert = row_to_dict(conn.execute("SELECT * FROM alerts").fetchone())
    lines = facts(alert)
    assert any("could be a false alarm" in ln for ln in lines)
    assert "scanning" in headline(alert)
    assert criteria(alert)[0]["observed"] == "12 of 12"


def test_shipped_model_card_is_complete():
    card = load_card(REPO / "models")
    if card is None:
        pytest.skip("model not trained")
    assert card["features"] == FEATURES
    assert card["test"]["accuracy"] > 0.95
    assert set(card["classes"]) >= {"benign", "scan", "dos", "brute_force"}
    assert len(card["sha256"]) == 64


@pytest.mark.parametrize("reply_s", [0.00003, 0.003, 0.03])   # the router itself; a Wi-Fi device; a slow one
def test_real_model_catches_worm_style_probing_the_rules_miss(cfg, reply_s):
    """A device probing nmap's top-10 ports on three other devices stays under both rules (< 15 ports per
    host, < 10 hosts), but the shipped model adds the probes up across hosts, whatever the reply time.
    Each record has the shape Suricata logged for real nmap SYN probes (one SYN out, one RST back).
    See bench/ml_vs_rules.py for the full study."""
    from netwatch.detectors.scan import ScanDetector
    from netwatch.ml.model import get_model
    model = get_model(REPO / "models")
    if model is None:
        pytest.skip("model not trained")
    conn = db.connect(cfg.db_path)
    top10 = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]
    for h, host in enumerate(["192.168.1.1", "192.168.1.101", "192.168.1.102"]):
        for i, port in enumerate(top10):
            ts = 100 + h * 10 + i
            conn.execute(
                """INSERT INTO flows(ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in,
                                     bytes_out, bytes_in, flags_ts, flags_tc)
                   VALUES(?,?,'192.168.1.152',?,?,?,'TCP',1,1,60,54,2,20)""",
                (ts, ts + reply_s, 40000 + h * 100 + i, host, port))
    assert ScanDetector().run(conn, cfg, 90, 150) == []
    (a,) = MLDetector(model).run(conn, cfg, 90, 150)
    assert a.kind == "ml_scan" and a.device_ip == "192.168.1.152"
    assert a.evidence["target_count"] == 3


def test_tampered_model_file_is_refused(tmp_path):
    from netwatch.ml.model import FlowModel
    card = load_card(REPO / "models")
    if card is None:
        pytest.skip("model not trained")
    (tmp_path / "flow_classifier.json").write_text(json.dumps(card))
    (tmp_path / "flow_classifier.joblib").write_bytes(b"not the trained model")
    with pytest.raises(ValueError, match="checksum"):
        FlowModel(tmp_path)
