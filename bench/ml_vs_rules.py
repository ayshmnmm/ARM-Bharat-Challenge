"""What does the ML detector catch that the rules do not?

    .venv/bin/python bench/ml_vs_rules.py      # about a minute on the Pi; needs captures/nmap_scan.pcapng

The rules count one thing per pair of machines (ports on one host, or hosts from one source) and fire at a
fixed number. The ML detector judges each connection on its own and adds up attack-like connections from one
device across every host and port. This script measures where that difference matters.

Every scenario is built from the *real* probe records of the nmap capture (Suricata's own flow records of
nmap's SYN and connect scans of the router), re-addressed to other devices on the home network and re-timed.
The model never sees addresses. Probes of devices other than the router are given a Wi-Fi reply time
(3 ms) instead of the router's own ~30 µs; the model uses no timing features, so this does not change its
verdicts (an earlier model with timing features flagged none of them, which is why they were removed).

The port lists are nmap's standard "top 10" and "top 20" (`nmap --top-ports N`), not ports chosen to suit
the model. Results go to bench/ml_vs_rules.json and bench/ML_VS_RULES.md.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netwatch import db  # noqa: E402
from netwatch.config import REPO, load  # noqa: E402
from netwatch.detectors import run_range  # noqa: E402
from netwatch.detectors.ml import ML_MIN_FLOWS, ML_MIN_PROB  # noqa: E402
from netwatch.detectors.scan import PORT_SCAN_MIN_PORTS, SWEEP_MIN_HOSTS  # noqa: E402
from netwatch.ml.model import get_model  # noqa: E402
from netwatch.pipeline import replay  # noqa: E402

CAPTURE = REPO / "captures" / "nmap_scan.pcapng"
ATTACKER, ROUTER = "192.168.1.152", "192.168.1.1"
TOP10 = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]
TOP20 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
HOSTS = [ROUTER] + [f"192.168.1.{n}" for n in range(101, 109)]   # a home network: 9 other devices
T0 = 1_800_000_000.0
COLS = ["ts_start", "ts_end", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "app_proto", "pkts_out",
        "pkts_in", "bytes_out", "bytes_in", "state", "flags_ts", "flags_tc", "community_id"]


def real_probes(base) -> dict[str, dict[int, dict]]:
    """One real probe record per port for each nmap technique, from replaying the capture."""
    with tempfile.TemporaryDirectory(prefix="netwatch-mlvr-") as tmp:
        cfg = replace(base, home=Path(tmp), explainer="template")
        conn = db.connect(cfg.db_path)
        replay(conn, cfg, CAPTURE, explain=False)
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM flows WHERE proto='TCP' AND src_ip=? AND dst_ip=? ORDER BY ts_start", (ATTACKER, ROUTER))]
        conn.close()
    syn_sport = Counter(r["src_port"] for r in rows).most_common(1)[0][0]   # nmap -sS reuses one source port
    out: dict[str, dict[int, dict]] = {"SYN scan (-sS)": {}, "connect scan (-sT)": {}}
    for r in rows:
        kind = "SYN scan (-sS)" if r["src_port"] == syn_sport else "connect scan (-sT)"
        out[kind].setdefault(r["dst_port"], r)
    return out


def run(base, records: list[dict]) -> dict:
    """Load flow records into an empty database, run every detector, report what fired."""
    with tempfile.TemporaryDirectory(prefix="netwatch-mlvr-") as tmp:
        cfg = replace(base, home=Path(tmp), explainer="template")
        conn = db.connect(cfg.db_path)
        conn.executemany(f"INSERT INTO flows ({','.join(COLS)}) VALUES ({','.join('?' * len(COLS))})",
                         [[r[c] for c in COLS] for r in records])
        conn.commit()
        run_range(conn, cfg, min(r["ts_start"] for r in records), max(r["ts_end"] for r in records))
        alerts = [dict(a) for a in conn.execute("SELECT detector, kind, evidence FROM alerts")]
        conn.close()
    rules = sorted({a["kind"] for a in alerts if a["detector"] != "ml"})
    ml = sorted({a["kind"] for a in alerts if a["detector"] == "ml"}
                | {"ml_" + json.loads(a["evidence"])["ml"]["family"] for a in alerts
                   if a["detector"] != "ml" and '"ml"' in a["evidence"]})
    return {"rules": rules, "ml": ml}


WIFI_REPLY_S = 0.003   # a phone or laptop answers over Wi-Fi in milliseconds; the router itself in ~30 µs


def place(probes: dict[int, dict], ports: list[int], hosts: list[str], spread_s: float) -> list[dict]:
    """The given ports probed on each host in turn, evenly spaced over `spread_s` seconds.
    Each record keeps its real packets, bytes and flags. Probes of the router keep their real reply time;
    probes of other devices get a Wi-Fi reply time, as they would really have."""
    out, n = [], len(ports) * len(hosts)
    for k, (host, port) in enumerate((h, p) for h in hosts for p in ports):
        r = dict(probes[port])
        dur = r["ts_end"] - r["ts_start"] if host == ROUTER else max(r["ts_end"] - r["ts_start"], WIFI_REPLY_S)
        r["ts_start"] = T0 + k * spread_s / n
        r["ts_end"] = r["ts_start"] + dur
        r["dst_ip"] = host
        out.append(r)
    return out


def main() -> None:
    base = load()
    model = get_model(base.ml_dir)
    if model is None or not CAPTURE.exists():
        raise SystemExit("needs the trained model and captures/nmap_scan.pcapng")
    probes = real_probes(base)

    def flagged(technique: str, ports: list[int]) -> int:
        rows = [probes[technique][p] for p in ports]
        _, idx, prob = model.score(rows)
        return int(sum(model.classes[c] == "scan" and p >= ML_MIN_PROB for c, p in zip(idx, prob)))

    results = []

    def scenario(group: str, label: str, technique: str, ports: list[int], hosts: list[str], spread_s: float):
        ports = [p for p in ports if p in probes[technique]]
        res = run(base, place(probes[technique], ports, hosts, spread_s))
        row = {"group": group, "scenario": label, "technique": technique, "ports_per_host": len(ports),
               "hosts": len(hosts), "probes": len(ports) * len(hosts), "spread_s": spread_s,
               "probes_flagged_by_ml": flagged(technique, ports) * len(hosts), **res}
        results.append(row)
        print(json.dumps(row))

    for technique in probes:
        # 1. The original kind of scan: many ports on one device. Both should fire.
        top1000 = sorted(probes[technique])
        scenario("full scan", "1000 ports on the router in 10 s", technique, top1000, [ROUTER], 10)
        # 2. Lateral movement: a few login/file-sharing ports on every other device, as a worm would.
        #    Below the port-scan rule (< 15 ports per host) and the sweep rule (< 10 hosts).
        for ports, pname in [(TOP10, "top 10"), (TOP20, "top 20")]:
            for h in (1, 2, 3, 5, 9):
                scenario("lateral", f"nmap {pname} ports on {h} device{'s' if h > 1 else ''}, within 20 s",
                         technique, ports, HOSTS[:h], 20)
            scenario("lateral", f"nmap {pname} ports on 9 devices, spread over 10 min", technique, ports, HOSTS, 600)

    md = [
        "# ML vs rules: what each detector catches",
        "",
        f"Generated by `bench/ml_vs_rules.py`. Rules: port scan at ≥ {PORT_SCAN_MIN_PORTS} ports on one host, "
        f"sweep at ≥ {SWEEP_MIN_HOSTS} hosts, per 60 s window. ML: ≥ {ML_MIN_FLOWS} distinct connections judged "
        f"scanning at ≥ {ML_MIN_PROB:.0%} confidence from one device per 60 s window.",
        "",
        "Every probe is a real Suricata flow record from the nmap capture, re-addressed and re-timed; probes of "
        f"devices other than the router get a {WIFI_REPLY_S * 1000:g} ms Wi-Fi reply time.",
        "",
        "| Technique | Scenario | Probes | ML-flagged probes | Rules | ML |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        md.append(f"| {r['technique']} | {r['scenario']} | {r['probes']} | {r['probes_flagged_by_ml']} | "
                  f"{', '.join(r['rules']) or '—'} | {', '.join(r['ml']) or '—'} |")
    (REPO / "bench" / "ML_VS_RULES.md").write_text("\n".join(md) + "\n")
    (REPO / "bench" / "ml_vs_rules.json").write_text(json.dumps(results, indent=2) + "\n")

    # A short, plain-language version for the dashboard ("How it works"), kept in the model card.
    # A row counts as caught only if it was caught for every technique and every case in the group.
    groups = [
        ("A full scan: 1,000 services on one device", lambda r: r["group"] == "full scan"),
        ("The 20 most common services, on 1 to 9 devices", lambda r: r["ports_per_host"] == len(TOP20)),
        ("The 10 most common services, on one device",
         lambda r: r["ports_per_host"] == len(TOP10) and r["hosts"] == 1),
        ("The 10 most common services, on 2 to 9 devices at once",
         lambda r: r["ports_per_host"] == len(TOP10) and r["hosts"] > 1 and r["spread_s"] <= 60),
        ("The same, spread out over 10 minutes",
         lambda r: r["ports_per_host"] == len(TOP10) and r["spread_s"] > 60),
    ]
    summary = []
    for label, sel in groups:
        rows = [r for r in results if sel(r)]
        summary.append({"scenario": label, "cases": len(rows),
                        "rules": all(r["rules"] for r in rows), "ml": all(r["ml"] for r in rows)})
    card_path = base.ml_dir / "flow_classifier.json"
    card = json.loads(card_path.read_text())
    card["beyond_rules"] = summary
    card_path.write_text(json.dumps(card, indent=2) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
