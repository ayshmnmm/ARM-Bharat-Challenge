"""Detector registry and the event-time windowing loop.

Detectors look at fixed windows of *event time* (packet timestamps, not wall clock), so the
same code gives the same answers live and when replaying a pcap.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Protocol

from .. import db
from ..alerts import AlertDraft, upsert
from ..config import Config

WINDOW_S = 60
STEP_S = 30
# Live mode: flows are only logged once they end/time out, so stay this far behind the event clock.
LIVE_LAG_S = 20
# Flows logged later than that (long connections, logged when idle) re-open recent windows,
# up to this far back.
LATE_FLOW_MAX_S = 900


class Detector(Protocol):
    name: str

    def run(self, conn: sqlite3.Connection, cfg: Config, t0: float, t1: float) -> list[AlertDraft]: ...


def all_detectors(cfg: Config) -> list[Detector]:
    from .feeds import FeedDetector
    from .scan import ScanDetector

    from .baseline import BaselineDetector
    from .behaviour import BehaviourDetector

    dets: list = [ScanDetector(), FeedDetector(cfg), BehaviourDetector(), BaselineDetector()]
    if cfg.ml_enabled:
        from ..ml.model import get_model
        model = get_model(cfg.ml_dir)
        if model is not None:
            from .ml import MLDetector
            dets.append(MLDetector(model))  # last, so it can attach to rule alerts from the same window
    return dets


def run_range(conn: sqlite3.Connection, cfg: Config, start: float, end: float, detectors=None) -> int:
    """Run every detector over all windows covering [start, end]. Used for pcap replays."""
    detectors = detectors or all_detectors(cfg)
    t0 = start - (start % STEP_S) - STEP_S  # one step early so the first window fully covers `start`
    n = 0
    while t0 <= end:
        for det in detectors:
            for draft in det.run(conn, cfg, t0, t0 + WINDOW_S):
                upsert(conn, draft)
                n += 1
        t0 += STEP_S
    conn.commit()
    return n


def _next_event(conn: sqlite3.Connection, after: float) -> float | None:
    times = [conn.execute(f"SELECT MIN({col}) AS t FROM {table} WHERE {col} >= ?", (after,)).fetchone()["t"]
             for table, col in (("flows", "ts_start"), ("dns", "ts"), ("tls", "ts"), ("http", "ts"))]
    times = [t for t in times if t is not None]
    return min(times) if times else None


def run_pending(conn: sqlite3.Connection, cfg: Config, detectors=None, now: float | None = None) -> int:
    """Live mode: run every detector over complete windows not yet processed.

    The horizon follows the wall clock (minus LIVE_LAG_S for flows still being logged), so a scan
    is reported even if the network goes quiet right after it. Stretches with no events are skipped.
    """
    detectors = detectors or all_detectors(cfg)
    clock = db.get_meta(conn, "event_clock", 0.0) or 0.0
    if not clock:
        return 0
    horizon = max(clock, time.time() if now is None else now) - LIVE_LAG_S
    t0 = db.get_meta(conn, "detect_cursor", None)
    n = 0
    max_row = conn.execute("SELECT MAX(id) AS m FROM flows").fetchone()["m"] or 0
    if t0 is None:
        t0 = -float("inf")
    else:
        # Flows that arrived after their window was already processed.
        seen_row = db.get_meta(conn, "detect_flow_rowid", 0)
        late = conn.execute("SELECT MIN(ts_start) AS t FROM flows WHERE id > ? AND ts_start < ?",
                            (seen_row, t0 + WINDOW_S - STEP_S)).fetchone()["t"]
        if late is not None:
            start = max(late, t0 - LATE_FLOW_MAX_S)
            n += run_range(conn, cfg, start, t0, detectors)
    db.set_meta(conn, "detect_flow_rowid", max_row)
    while t0 + WINDOW_S <= horizon:
        nxt = _next_event(conn, t0 if t0 != -float("inf") else 0)
        if nxt is None:
            break  # nothing new: keep the cursor so late-logged flows are still covered
        if nxt >= t0 + WINDOW_S:
            t0 = nxt - (nxt % STEP_S) - STEP_S  # jump over the empty stretch
            if t0 + WINDOW_S > horizon:
                break
        for det in detectors:
            for draft in det.run(conn, cfg, t0, t0 + WINDOW_S):
                upsert(conn, draft)
                n += 1
        t0 += STEP_S
    if t0 != -float("inf"):
        db.set_meta(conn, "detect_cursor", t0)
    conn.commit()
    return n
