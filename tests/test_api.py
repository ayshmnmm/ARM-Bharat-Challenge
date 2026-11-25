from __future__ import annotations

import ast
from pathlib import Path

from fastapi.testclient import TestClient

from netwatch import db
from netwatch.__main__ import main
from netwatch.api import create_app
from netwatch.pipeline import replay

from .conftest import REPO, needs_suricata


@needs_suricata
def test_api_end_to_end(cfg, lab_pcaps):
    conn = db.connect(cfg.db_path)
    replay(conn, cfg, lab_pcaps / "lab_phishing_visit.pcap")
    replay(conn, cfg, lab_pcaps / "lab_ssh_bruteforce.pcap")
    c = TestClient(create_app(cfg))

    ov = c.get("/api/overview").json()
    assert ov["alerts_total"] == 2 and ov["alerts_open"]["high"] == 2 and ov["devices_total"] == 2

    alerts = c.get("/api/alerts").json()
    a = next(x for x in alerts if x["kind"] == "lab_domain")
    detail = c.get(f"/api/alerts/{a['id']}").json()
    assert detail["explanation"]["summary"]
    acts = {x["action"] for x in detail["actions"]}
    assert {"quarantine_device", "block_domain", "snooze"} <= acts
    assert "203.0.113.10" in next(x for x in detail["actions"] if x["action"] == "block_domain")["command_preview"]

    r = c.post(f"/api/alerts/{a['id']}/actions", json={"action": "quarantine_device"}).json()
    assert r["status"] == "not_executed" and "nft" in r["command_preview"]
    assert c.post(f"/api/alerts/{a['id']}/actions", json={"action": "rm -rf"}).status_code == 400

    assert c.post(f"/api/alerts/{a['id']}/status", json={"status": "acknowledged"}).json()["status"] == "acknowledged"
    assert c.post(f"/api/alerts/{a['id']}/status", json={"status": "bogus"}).status_code == 422

    dev = c.get("/api/devices/192.168.1.50").json()
    assert dev["device"]["ip"] == "192.168.1.50" and dev["alerts"]
    assert any(t["sni"] == "login-verify-account.netwatch-lab.test" for t in dev["tls"])
    assert c.get("/api/devices/10.9.9.9").status_code == 404
    assert any(e["type"] == "action" for e in c.get("/api/timeline").json())
    assert "cpu_percent" in c.get("/api/system").json()


def test_system_page_survives_unreadable_sensor_dir(cfg, tmp_path):
    """The installed sensor's directory belongs to the service user; a dev API run as the login user
    must still serve /api/system, just without the sensor's last-write time."""
    locked = tmp_path / "sensor"
    locked.mkdir()
    (locked / "eve.json").write_text("")
    locked.chmod(0)
    try:
        r = TestClient(create_app(cfg, eve_path=locked / "eve.json")).get("/api/system")
    finally:
        locked.chmod(0o755)
    assert r.status_code == 200 and r.json()["sensor_last_write_s"] is None


def test_reset_continues_from_the_end_of_the_sensor_log(cfg, tmp_path):
    from netwatch.ingest.eve import Tail
    eve = tmp_path / "eve.json"
    eve.write_text('{"event_type": "flow"}\n' * 3)
    assert main(["reset", "--eve", str(eve)]) == 0
    tail = Tail(db.connect(cfg.db_path), cfg, eve)
    assert tail.offset == eve.stat().st_size and tail.poll() == 0   # old events are not re-read


def test_reset_keeps_learned_baselines_unless_asked(cfg, tmp_path):
    from netwatch.detectors.baseline import SCHEMA
    conn = db.connect(cfg.db_path)
    conn.executescript(SCHEMA)
    conn.execute("INSERT INTO device_baseline VALUES ('192.168.1.60', 'upload_bytes', 500, 7e4, 1e9, 4e6, 1.8e9)")
    conn.execute("INSERT INTO alerts (dedup_key, detector, kind, severity, title, ts_first, ts_last, evidence) "
                 "VALUES ('k', 'scan', 'port_scan', 'high', 't', 1, 2, '{}')")
    conn.commit()
    conn.close()
    eve = tmp_path / "eve.json"
    eve.write_text("")
    assert main(["reset", "--eve", str(eve)]) == 0
    conn = db.connect(cfg.db_path)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert [tuple(r) for r in conn.execute("SELECT ip, n FROM device_baseline")] == [("192.168.1.60", 500)]
    conn.close()
    assert main(["reset", "--eve", str(eve), "--forget-baselines"]) == 0
    conn = db.connect(cfg.db_path)
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='device_baseline'").fetchone() is None


def test_alert_lists_put_the_latest_raised_alert_on_top(cfg):
    """A replayed capture stamped in the past, raised after a live alert, is listed first."""
    from netwatch.alerts import AlertDraft, upsert
    conn = db.connect(cfg.db_path)
    upsert(conn, AlertDraft("intrusion", "port_scan", "high", "live", "192.168.1.60", "192.168.1.1", 5000, 5010))
    upsert(conn, AlertDraft("feeds", "lab_domain", "high", "replayed", "192.168.1.50", "x.test", 1000, 1001))
    conn.commit()
    client = TestClient(create_app(cfg))
    assert [a["title"] for a in client.get("/api/alerts").json()] == ["replayed", "live"]
    assert [a["title"] for a in client.get("/api/overview").json()["recent_alerts"]] == ["replayed", "live"]


def test_serve_refuses_unsafe_bind(cfg, capsys):
    assert main(["serve", "--host", "0.0.0.0"]) == 2
    assert main(["serve", "--host", "10.4.20.16"]) == 2
    assert "Refusing" in capsys.readouterr().err


def test_actions_module_cannot_execute_anything():
    """M5 is dry-run only: the module must not import anything able to run commands."""
    tree = ast.parse(Path(REPO / "netwatch" / "actions.py").read_text())
    imported = {n.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                for n in node.names} | {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"subprocess", "os", "shlex", "pty", "nftables"}


def test_block_ip_only_offered_for_public_addresses():
    from netwatch.actions import available
    base = {"kind": "brute_force", "device_ip": "192.168.1.60"}
    assert "block_ip" not in available({**base, "peer": "192.168.1.1"})
    assert "block_ip" in available({**base, "peer": "8.8.8.8"})
    assert "block_ip" not in available({**base, "kind": "phishing_domain", "peer": "evil.example"})


@needs_suricata
def test_alert_explains_which_rule_fired(lab_pcaps, cfg):
    """Every alert kind the lab produces carries 'why it was flagged' rows that use the detector thresholds."""
    from netwatch.detectors.scan import BRUTE_MIN_CONNS, FLOOD_MIN_SYNS
    conn = db.connect(cfg.db_path)
    for p in sorted(lab_pcaps.glob("*.pcap")):
        replay(conn, cfg, p)
    client = TestClient(create_app(cfg))
    rules = {}
    for a in client.get("/api/alerts").json():
        rows = client.get(f"/api/alerts/{a['id']}").json()["criteria"]
        assert rows and all({"check", "observed", "rule", "met"} <= set(r) for r in rows), a["kind"]
        rules[a["kind"]] = " ".join(r["rule"] for r in rows)
    assert {"brute_force", "syn_flood", "host_sweep", "lab_domain"} <= set(rules)
    assert f"{BRUTE_MIN_CONNS}+" in rules["brute_force"] and f"{FLOOD_MIN_SYNS}+" in rules["syn_flood"]


def test_pin_protects_the_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from netwatch.api import create_app
    from netwatch.config import load
    monkeypatch.setenv("NETWATCH_HOME", str(tmp_path))
    monkeypatch.setenv("NETWATCH_PIN", "2468")
    client = TestClient(create_app(load()))
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/auth").json() == {"pin_required": True, "logged_in": False}
    assert client.post("/api/login", json={"pin": "0000"}).status_code == 401
    assert client.post("/api/login", json={"pin": "2468"}).status_code == 200
    assert client.get("/api/overview").status_code == 200
    for _ in range(5):
        client.post("/api/login", json={"pin": "1"})
    assert client.post("/api/login", json={"pin": "2468"}).status_code == 429  # rate limited


def test_weekly_summary_without_llama(cfg):
    from fastapi.testclient import TestClient

    from netwatch import db, summary
    from netwatch.api import create_app
    out = summary.write(db.connect(cfg.db_path), cfg)
    assert out["provider"] == "rules" and out["what"] and out["facts"][0].startswith("Period")
    client = TestClient(create_app(cfg))
    assert client.get("/api/summary").json()["summary"]["what"] == out["what"]
    assert client.post("/api/summary").json() == {"writing": True}
    from netwatch.pipeline import background_jobs
    assert background_jobs(db.connect(cfg.db_path), cfg) == 1
    assert client.get("/api/summary").json()["writing"] is False
