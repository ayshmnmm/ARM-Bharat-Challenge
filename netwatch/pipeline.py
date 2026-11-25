"""End-to-end runs: offline pcap replay and the live loop."""

from __future__ import annotations

import logging
import shutil
import subprocess
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import psutil

from . import db
from .config import Config
from .detectors import run_pending, run_range
from .explain import explain_pending
from .ingest.eve import Tail, ingest_file

log = logging.getLogger("netwatch")


def run_suricata_offline(cfg: Config, pcap: Path, out_dir: Path) -> Path:
    """Suricata in pcap-file mode as the current user: reads the file, never touches an interface."""
    if not shutil.which("suricata"):
        raise SystemExit("suricata not installed: run setup/install_deps.sh")
    cmd = ["nice", "-n", "10", "suricata", "-c", str(cfg.suricata_config), "--disable-detection",
           "-r", str(pcap), "-l", str(out_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    eve = out_dir / "eve.json"
    if proc.returncode != 0 or not eve.exists():
        raise RuntimeError(f"suricata failed ({proc.returncode}): {proc.stderr[-800:]}")
    return eve


def replay(conn: sqlite3.Connection, cfg: Config, pcap: Path, explain: bool = True) -> dict:
    t = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="netwatch-") as tmp:
        eve = run_suricata_offline(cfg, pcap, Path(tmp))
        t_sensor = time.monotonic() - t
        ing = ingest_file(conn, cfg, eve)
        n_events = ing.count
    t_ingest = time.monotonic() - t - t_sensor
    # Detect over exactly this capture's time range (independent of the live cursor).
    n_alerts = run_range(conn, cfg, ing.first_ts, ing.last_ts) if ing.first_ts is not None else 0
    t_detect = time.monotonic() - t - t_sensor - t_ingest
    n_explained = 0
    if explain:
        while explain_pending(conn, cfg, limit=10):
            n_explained += 1
    return {
        "pcap": str(pcap), "events": n_events, "alert_updates": n_alerts,
        "alerts_total": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "sensor_s": round(t_sensor, 2), "ingest_s": round(t_ingest, 2), "detect_s": round(t_detect, 2),
        "total_s": round(time.monotonic() - t, 2),
    }


class MemoryBudgetExceeded(SystemExit):
    pass


def _check_memory(cfg: Config) -> None:
    """The Pi's kernel has the memory cgroup disabled, so systemd can't cap RSS; enforce it here.
    Exiting lets systemd restart us with a clean heap instead of squeezing the router."""
    rss_mb = psutil.Process().memory_info().rss / 2**20
    if rss_mb > cfg.max_rss_mb:
        log.error("live: RSS %.0f MB over budget %d MB, exiting for a clean restart", rss_mb, cfg.max_rss_mb)
        raise MemoryBudgetExceeded(3)


def background_jobs(conn: sqlite3.Connection, cfg: Config) -> int:
    """One unit of slow writing work: an alert explanation first, then the weekly summary if someone
    asked for it. Returns how many jobs ran."""
    from . import summary

    n = explain_pending(conn, cfg, limit=1)
    if not n and db.get_meta(conn, "summary_requested", False):
        try:
            summary.write(conn, cfg)
        finally:
            db.set_meta(conn, "summary_requested", False)
            conn.commit()
        n = 1
    return n


def _explain_worker(cfg: Config, idle_s: float = 5.0, stop: threading.Event | None = None) -> None:
    """One explanation at a time, most severe first, on its own DB connection."""
    conn = db.connect(cfg.db_path)
    stop = stop or threading.Event()
    while not stop.is_set():
        try:
            n = background_jobs(conn, cfg)
        except Exception:
            log.exception("explain: failed, retrying")
            n = 0
        if not n:
            stop.wait(idle_s)


def run_live(conn: sqlite3.Connection, cfg: Config, eve_path: Path, interval_s: float = 5.0,
             max_cycles: int | None = None) -> None:
    """Tail the live sensor's eve.json; detect; explain one alert per cycle (keeps CPU for routing)."""
    tail = Tail(conn, cfg, eve_path)
    last_prune = 0.0
    # Llama takes about a minute per alert on the Pi: run it beside detection, not inside it.
    explain_inline = cfg.explainer != "llama"
    if not explain_inline:
        threading.Thread(target=_explain_worker, args=(cfg,), name="explain", daemon=True).start()
    log.info("live: following %s", eve_path)
    cycles = 0
    while max_cycles is None or cycles < max_cycles:
        cycles += 1
        cycle = time.monotonic()
        _check_memory(cfg)
        n = tail.poll()
        while n == 20000:  # catch up on a backlog in chunks
            n = tail.poll()
        run_pending(conn, cfg)
        if explain_inline:
            background_jobs(conn, cfg)
        if time.time() - last_prune > 3600:
            db.prune(conn, time.time() - cfg.retention_days * 86400)
            last_prune = time.time()
        if max_cycles is None or cycles < max_cycles:
            time.sleep(max(0.5, interval_s - (time.monotonic() - cycle)))
