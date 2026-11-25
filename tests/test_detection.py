"""End-to-end: synthetic pcap -> Suricata -> ingest -> detectors -> explanation."""

from __future__ import annotations

import pytest

from netwatch import db
from netwatch.pipeline import replay

from .conftest import needs_suricata

pytestmark = needs_suricata


def _alerts(cfg, pcap):
    conn = db.connect(cfg.db_path)
    replay(conn, cfg, pcap)
    return conn, [dict(r) for r in conn.execute("SELECT * FROM alerts")]


@pytest.mark.parametrize("pcap, kind, severity", [
    ("lab_syn_flood.pcap", "syn_flood", "high"),
    ("lab_ssh_bruteforce.pcap", "brute_force", "high"),
    ("lab_host_sweep.pcap", "host_sweep", "medium"),
    ("lab_phishing_visit.pcap", "lab_domain", "high"),
    ("lab_phishing_lookup.pcap", "lab_domain", "medium"),
    ("lab_beaconing.pcap", "beaconing", "medium"),
    ("lab_dga.pcap", "dga", "high"),
    ("lab_dns_tunnel.pcap", "dns_tunnel", "high"),
    ("lab_lateral_probe.pcap", "ml_scan", "medium"),   # no rule fires; only the AI detector
])
def test_lab_attack_detected(cfg, lab_pcaps, pcap, kind, severity):
    conn, alerts = _alerts(cfg, lab_pcaps / pcap)
    assert [(a["kind"], a["severity"]) for a in alerts] == [(kind, severity)]
    # every alert gets an explanation
    assert conn.execute("SELECT COUNT(*) FROM explanations").fetchone()[0] == len(alerts)


def test_phishing_visit_seen_on_dns_and_sni(cfg, lab_pcaps):
    import json
    _, alerts = _alerts(cfg, lab_pcaps / "lab_phishing_visit.pcap")
    ev = json.loads(alerts[0]["evidence"])
    assert ev["connected"] is True
    assert set(ev["seen_via"]) == {"DNS lookup", "HTTPS (TLS SNI)"}
    assert ev["connected_ips"] == ["203.0.113.10"]
    assert alerts[0]["device_ip"] == "192.168.1.50"


def test_devices_identified(cfg, lab_pcaps):
    conn, _ = _alerts(cfg, lab_pcaps / "lab_phishing_visit.pcap")
    dev = dict(conn.execute("SELECT * FROM devices WHERE ip='192.168.1.50'").fetchone())
    assert dev["mac_random"] == 1
    assert dev["kind"].startswith("Phone")
    # broadcast/network addresses are never devices
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE ip LIKE '%.255'").fetchone()[0] == 0


def test_replay_is_idempotent_per_db(cfg, lab_pcaps):
    """Replaying more captures into the same DB keeps earlier alerts and adds new ones."""
    conn = db.connect(cfg.db_path)
    replay(conn, cfg, lab_pcaps / "lab_syn_flood.pcap")
    replay(conn, cfg, lab_pcaps / "lab_host_sweep.pcap")
    kinds = sorted(r[0] for r in conn.execute("SELECT kind FROM alerts"))
    assert kinds == ["host_sweep", "syn_flood"]


def test_inside_attacker_owns_the_alert(cfg, lab_pcaps):
    """Attacks from a Wi-Fi client are filed under that client, not under the router it hit."""
    for pcap in ("lab_syn_flood.pcap", "lab_ssh_bruteforce.pcap"):
        _, alerts = _alerts(cfg, lab_pcaps / pcap)
        assert alerts[-1]["device_ip"] == "192.168.1.60"


def test_overlapping_windows_do_not_inflate_count(cfg, lab_pcaps):
    _, alerts = _alerts(cfg, lab_pcaps / "lab_ssh_bruteforce.pcap")
    assert alerts[0]["count"] == 1
