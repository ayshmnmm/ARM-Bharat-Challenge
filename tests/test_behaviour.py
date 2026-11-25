"""M1 baselines and M2 metadata detectors on hand-built records (no Suricata needed)."""

from __future__ import annotations

from netwatch import db
from netwatch.detectors.baseline import LEARN_MINUTES, BaselineDetector
from netwatch.detectors.behaviour import FINGERPRINT_LEARN_S, BehaviourDetector, looks_random


def test_random_labels_vs_real_names():
    assert looks_random("x7kq2mz9vtr4pl")
    assert not looks_random("googleapis") and not looks_random("whatsapp") and not looks_random("netflix")


def _minute(conn, t0, ip="192.168.1.70", up=100_000, dsts=3):
    for i in range(dsts):
        conn.execute("""INSERT INTO flows(ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in,
                        bytes_out, bytes_in, flags_ts, flags_tc) VALUES(?,?,?,?,?,443,'TCP',10,10,?,500,27,27)""",
                     (t0 + 1 + i, t0 + 2 + i, ip, 40000 + i, f"203.0.113.{i + 1}", up // dsts))


def test_baseline_learns_then_flags_a_big_upload(cfg):
    conn = db.connect(cfg.db_path)
    det = BaselineDetector()
    for m in range(LEARN_MINUTES):
        t0 = 60_000 + m * 60
        _minute(conn, t0, up=100_000 + (m % 7) * 10_000)
        assert det.run(conn, cfg, t0, t0 + 60) == []
    t0 = 60_000 + LEARN_MINUTES * 60
    _minute(conn, t0, up=400_000_000)
    (a,) = det.run(conn, cfg, t0, t0 + 60)
    assert a.kind == "unusual_upload" and a.evidence["times_above_usual"] > 1000
    assert det.run(conn, cfg, t0, t0 + 60) == []  # the same minute is never counted twice


def test_baseline_needs_learning_first(cfg):
    conn = db.connect(cfg.db_path)
    _minute(conn, 60_000, up=900_000_000)
    assert BaselineDetector().run(conn, cfg, 60_000, 60_060) == []


def test_new_fingerprint_only_after_learning_and_if_unknown_everywhere(cfg):
    conn = db.connect(cfg.db_path)
    conn.execute("INSERT INTO devices(ip, first_seen, last_seen) VALUES('192.168.1.70', 0, 0)")
    conn.execute("INSERT INTO devices(ip, first_seen, last_seen) VALUES('192.168.1.80', 0, 0)")
    t = FINGERPRINT_LEARN_S + 1000
    conn.execute("INSERT INTO tls(ts, src_ip, dst_ip, sni, ja4) VALUES(?, '192.168.1.70', '1.2.3.4', 'a.example', 'old')", (t - 500,))
    conn.execute("INSERT INTO tls(ts, src_ip, dst_ip, sni, ja4) VALUES(?, '192.168.1.80', '1.2.3.4', 'b.example', 'shared')", (t - 500,))
    conn.execute("INSERT INTO tls(ts, src_ip, dst_ip, sni, ja4) VALUES(?, '192.168.1.70', '5.6.7.8', 'x.example', 'brandnew')", (t + 5,))
    conn.execute("INSERT INTO tls(ts, src_ip, dst_ip, sni, ja4) VALUES(?, '192.168.1.70', '5.6.7.8', 'y.example', 'shared')", (t + 6,))
    (a,) = BehaviourDetector()._fingerprints(conn, cfg, t, t + 60)
    assert a.kind == "new_fingerprint" and a.evidence["ja4"] == "brandnew"


def _checkins(conn, sport_of, n=12, period=45.0):
    for i in range(n):
        t = 10_000 + i * period
        conn.execute("""INSERT INTO flows(ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in,
                        bytes_out, bytes_in, flags_ts, flags_tc) VALUES(?,?,'192.168.1.199',?,'142.250.134.95',443,
                        'TCP',1,1,66,66,16,16)""", (t, t + 0.1, sport_of(i)))


def test_one_long_keepalive_connection_is_not_beaconing(cfg):
    """Seen live: a laptop's single keep-alive connection to Google, which Suricata logged as a record every
    ~45 s. Same addresses and source port throughout, so it is one connection, not repeated check-ins."""
    conn = db.connect(cfg.db_path)
    _checkins(conn, lambda i: 51272)
    assert BehaviourDetector()._beacons(conn, cfg, 10_400, 10_600) == []


def test_flood_is_not_hidden_by_unrelated_probes_of_the_same_device(cfg):
    from netwatch.detectors.scan import ScanDetector
    conn = db.connect(cfg.db_path)
    rows = [(100 + i * 0.002, "192.168.1.60", 40000 + i, 3000) for i in range(250)]          # the flood
    rows += [(110 + i, "192.168.1.70", 51234, port) for i, port in enumerate(range(20, 32))]  # a camera's probes
    for ts, src, sport, dport in rows:
        conn.execute("""INSERT INTO flows(ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in,
                        bytes_out, bytes_in, flags_ts, flags_tc) VALUES(?,?,?,?,'192.168.1.1',?,'TCP',1,0,60,0,2,0)""",
                     (ts, ts, src, sport, dport))
    floods = ScanDetector()._floods(cfg, conn.execute("SELECT * FROM flows").fetchall())
    assert [(a.kind, a.evidence["syn_count"], a.evidence["ports"]) for a in floods] == [("syn_flood", 250, [3000])]


def test_windows_connect_scan_with_syn_retries_is_a_port_scan(cfg):
    """Windows retries a refused connection: 5 SYNs (330 bytes) per closed port, as logged live on this network."""
    from netwatch.detectors.scan import ScanDetector
    conn = db.connect(cfg.db_path)
    for i, port in enumerate(range(1, 41)):
        conn.execute("""INSERT INTO flows(ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, proto, pkts_out, pkts_in,
                        bytes_out, bytes_in, flags_ts, flags_tc) VALUES(?,?,'192.168.1.199',?,'192.168.1.1',?,'TCP',5,5,330,270,2,20)""",
                     (100 + i * 0.05, 102 + i * 0.05, 55000 + i, port))
    (a,) = ScanDetector()._port_scans(cfg, conn.execute("SELECT * FROM flows").fetchall())
    assert a.kind == "port_scan" and a.evidence["ports_probed"] == 40


def test_new_connection_every_period_is_beaconing(cfg):
    conn = db.connect(cfg.db_path)
    _checkins(conn, lambda i: 41000 + i)
    (a,) = BehaviourDetector()._beacons(conn, cfg, 10_400, 10_600)
    assert a.kind == "beaconing" and a.evidence["check_ins"] == 12
