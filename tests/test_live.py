"""Live mode: tailing a growing sensor log, rotation, and alerts on a network that goes quiet."""

from __future__ import annotations

import pytest

from netwatch import db
from netwatch.pipeline import MemoryBudgetExceeded, run_live, run_suricata_offline

from .conftest import needs_suricata

pytestmark = needs_suricata


def _eve_lines(cfg, pcap, tmp_path):
    out = tmp_path / f"sensor-{pcap.stem}"
    out.mkdir()
    return run_suricata_offline(cfg, pcap, out).read_text().splitlines(keepends=True)


def test_live_tail_detects_and_survives_rotation(cfg, lab_pcaps, tmp_path):
    eve = tmp_path / "eve.json"
    conn = db.connect(cfg.db_path)

    # The sensor writes the SSH-guessing traffic in three chunks, the last ending mid-line.
    lines = _eve_lines(cfg, lab_pcaps / "lab_ssh_bruteforce.pcap", tmp_path)
    third = len(lines) // 3
    with open(eve, "w") as fh:
        fh.writelines(lines[:third])
    run_live(conn, cfg, eve, interval_s=0, max_cycles=1)
    with open(eve, "a") as fh:
        fh.writelines(lines[third:2 * third])
        fh.write(lines[2 * third][:10])  # partial line: must not be consumed yet
    run_live(conn, cfg, eve, interval_s=0, max_cycles=1)
    with open(eve, "a") as fh:
        fh.write(lines[2 * third][10:])
        fh.writelines(lines[2 * third + 1:])
    # No further traffic after this: the alert must still appear (network went quiet).
    run_live(conn, cfg, eve, interval_s=0, max_cycles=1)
    kinds = [r["kind"] for r in conn.execute("SELECT kind FROM alerts")]
    assert kinds == ["brute_force"]
    assert conn.execute("SELECT COUNT(*) FROM explanations").fetchone()[0] == 1

    # logrotate copytruncate: the file is truncated and the sensor keeps appending.
    flood = _eve_lines(cfg, lab_pcaps / "lab_syn_flood.pcap", tmp_path)
    eve.write_text("")
    run_live(conn, cfg, eve, interval_s=0, max_cycles=1)
    with open(eve, "a") as fh:
        fh.writelines(flood)
    run_live(conn, cfg, eve, interval_s=0, max_cycles=1)
    kinds = sorted(r["kind"] for r in conn.execute("SELECT kind FROM alerts"))
    assert kinds == ["brute_force", "syn_flood"]


def test_live_exits_when_over_memory_budget(cfg, tmp_path, monkeypatch):
    from netwatch.config import load
    monkeypatch.setenv("NETWATCH_MAX_RSS_MB", "1")
    tight = load()
    with pytest.raises(MemoryBudgetExceeded):
        run_live(db.connect(tight.db_path), tight, tmp_path / "eve.json", interval_s=0, max_cycles=1)


def test_late_long_flow_to_listed_ip_is_still_checked(cfg, tmp_path, monkeypatch):
    """A long connection is only logged when it goes idle, after its window was processed."""
    import time as _t

    from netwatch.detectors import run_pending
    from netwatch.ingest.eve import Ingestor

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "c2.txt").write_text("198.51.100.66\n")
    (bundle / "manifest.json").write_text(
        '{"feeds":[{"name":"c2","kind":"ip","category":"c2","file":"c2.txt"}]}')
    monkeypatch.setenv("NETWATCH_FEEDS_DIR", str(bundle))
    from netwatch.config import load
    c = load()
    conn = db.connect(c.db_path)
    ing = Ingestor(conn, c)
    now = _t.time()

    def flow(start, end, dst, port=443):
        iso = lambda t: _t.strftime("%Y-%m-%dT%H:%M:%S", _t.localtime(t)) + f".000000{_t.strftime('%z')}"
        return ('{"timestamp":"%s","event_type":"flow","src_ip":"192.168.1.50","src_port":40000,'
                '"dest_ip":"%s","dest_port":%d,"proto":"TCP","flow":{"pkts_toserver":50,"pkts_toclient":50,'
                '"bytes_toserver":9000,"bytes_toclient":9000,"start":"%s","end":"%s","state":"closed"}}\n'
                % (iso(end), dst, port, iso(start), iso(end)))

    ing.feed([flow(now - 400, now - 390, "93.184.215.14")])   # ordinary traffic, processed live
    run_pending(conn, c, now=now)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    # The C2 connection started 6 minutes ago and is only logged now.
    ing.feed([flow(now - 360, now - 10, "198.51.100.66")])
    run_pending(conn, c, now=now + 30)
    assert [r["kind"] for r in conn.execute("SELECT kind FROM alerts")] == ["c2_ip"]
