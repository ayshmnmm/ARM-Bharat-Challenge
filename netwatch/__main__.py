"""NetWatch command line.

  python -m netwatch replay captures/nmap_scan.pcapng   # offline: pcap -> Suricata -> detect -> explain
  python -m netwatch live --eve /var/lib/netwatch/sensor/eve.json
  python -m netwatch serve                              # dashboard + API on 192.168.1.1:8088
  python -m netwatch explain                            # explain any unexplained alerts
  python -m netwatch reset                              # delete alerts and traffic; keep each device's learned normal
  python -m netwatch feeds-build                        # LAPTOP ONLY: build a threat-feed bundle
  python -m netwatch ml-train --data DIR                 # train the flow classifier on CIC-IDS2017
  python -m netwatch ml-eval                            # check it on this network's own captures
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from pathlib import Path

from . import db
from .config import ALLOWED_BIND_HOSTS, load


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="netwatch")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("replay")
    p.add_argument("pcap", nargs="+", type=Path)
    p.add_argument("--no-explain", action="store_true")
    p = sub.add_parser("live")
    p.add_argument("--eve", type=Path, default=Path("/var/lib/netwatch/sensor/eve.json"))
    p = sub.add_parser("serve")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--eve", type=Path, default=Path("/var/lib/netwatch/sensor/eve.json"))
    sub.add_parser("explain")
    p = sub.add_parser("reset")
    p.add_argument("--eve", type=Path, default=Path("/var/lib/netwatch/sensor/eve.json"))
    p.add_argument("--forget-baselines", action="store_true",
                   help="also forget each device's learned normal traffic (relearning takes 2 active hours)")
    p = sub.add_parser("feeds-build")
    p.add_argument("--from", dest="raw_dir", type=Path, help="parse downloaded <name>.txt files here; no network")
    sub.add_parser("ml-eval")
    p = sub.add_parser("ml-train")
    p.add_argument("--data", type=Path, default=Path("var/datasets/cic/MachineLearningCVE"))
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "models")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load()

    if args.cmd == "replay":
        from .pipeline import replay
        conn = db.connect(cfg.db_path)
        for pcap in args.pcap:
            print(json.dumps(replay(conn, cfg, pcap, explain=not args.no_explain), indent=2))
    elif args.cmd == "live":
        from .pipeline import run_live
        run_live(db.connect(cfg.db_path), cfg, args.eve)
    elif args.cmd == "serve":
        import uvicorn

        from .api import create_app
        host = args.host or cfg.bind_host
        if host not in ALLOWED_BIND_HOSTS:
            print(f"Refusing to bind to {host}: only {sorted(ALLOWED_BIND_HOSTS)} are allowed "
                  "(never 0.0.0.0 or the campus-facing eth0 address).", file=sys.stderr)
            return 2
        uvicorn.run(create_app(cfg, args.eve), host=host, port=args.port or cfg.bind_port, log_level="warning")
    elif args.cmd == "explain":
        from .explain import explain_pending
        conn = db.connect(cfg.db_path)
        n = 0
        while explain_pending(conn, cfg, limit=10):
            n += 1
        print(f"explained batches: {n}")
    elif args.cmd == "reset":
        # Each device's learned normal (M1 baselines) is the home's normal, not demo clutter: keep it unless asked.
        kept = []
        if not args.forget_baselines and Path(cfg.db_path).exists():
            try:
                old = sqlite3.connect(cfg.db_path)
                kept = old.execute("SELECT * FROM device_baseline").fetchall()
                old.close()
            except sqlite3.Error:
                kept = []
        for suffix in ("", "-wal", "-shm"):
            Path(f"{cfg.db_path}{suffix}").unlink(missing_ok=True)
        print(f"removed alerts, devices and traffic from {cfg.db_path}")
        conn = db.connect(cfg.db_path)
        if kept:
            from .detectors.baseline import SCHEMA
            conn.executescript(SCHEMA)
            conn.executemany(f"INSERT INTO device_baseline VALUES ({','.join('?' * len(kept[0]))})", kept)
            print(f"kept the learned normal traffic of {len({r[0] for r in kept})} devices")
        try:  # live monitoring carries on from now, instead of re-reading the whole sensor log
            st = args.eve.stat()
        except OSError:
            st = None
        if st is not None:
            db.set_meta(conn, "tail_state", {"inode": st.st_ino, "offset": st.st_size})
            print(f"live monitoring continues from the end of {args.eve}")
        conn.commit()
    elif args.cmd == "feeds-build":
        from .feedbuild import build
        build(raw_dir=args.raw_dir)
    elif args.cmd == "ml-train":
        from .ml.train import train
        train(args.data, args.out)
    elif args.cmd == "ml-eval":
        from .ml.evaluate import evaluate
        evaluate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
