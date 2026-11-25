"""SQLite store. One file, WAL mode, so the API can read while ingest writes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    ip          TEXT PRIMARY KEY,        -- devices are keyed by IP: bridged VMs share their host's MAC
    mac         TEXT,
    mac_random  INTEGER DEFAULT 0,       -- locally administered (randomised) MAC
    vendor      TEXT,
    hostname    TEXT,
    kind        TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    bytes_up    INTEGER DEFAULT 0,
    bytes_down  INTEGER DEFAULT 0,
    flows       INTEGER DEFAULT 0,
    trusted     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY,
    ts_start    REAL NOT NULL,
    ts_end      REAL NOT NULL,
    src_ip      TEXT, src_port INTEGER,
    dst_ip      TEXT, dst_port INTEGER,
    proto       TEXT, app_proto TEXT,
    pkts_out    INTEGER, pkts_in INTEGER,
    bytes_out   INTEGER, bytes_in INTEGER,
    state       TEXT,
    flags_ts    INTEGER, flags_tc INTEGER,   -- TCP flags seen client->server / server->client
    community_id TEXT
);
CREATE INDEX IF NOT EXISTS flows_ts ON flows(ts_start);
CREATE INDEX IF NOT EXISTS flows_src ON flows(src_ip, ts_start);
CREATE INDEX IF NOT EXISTS flows_dst ON flows(dst_ip, ts_start);

CREATE TABLE IF NOT EXISTS dns (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, src_ip TEXT,
    rrname TEXT, rrtype TEXT, rcode TEXT, answers TEXT
);
CREATE INDEX IF NOT EXISTS dns_ts ON dns(ts);
CREATE INDEX IF NOT EXISTS dns_src ON dns(src_ip, ts);

CREATE TABLE IF NOT EXISTS tls (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
    transport TEXT, sni TEXT, version TEXT, ja3 TEXT, ja4 TEXT, subject TEXT, issuer TEXT
);
CREATE INDEX IF NOT EXISTS tls_ts ON tls(ts);
CREATE INDEX IF NOT EXISTS tls_src ON tls(src_ip, ts);

CREATE TABLE IF NOT EXISTS http (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
    host TEXT, url TEXT, method TEXT, user_agent TEXT, status INTEGER
);
CREATE INDEX IF NOT EXISTS http_ts ON http(ts);

-- domain -> IP from DNS answers, so connections to those IPs can be attributed to a domain
CREATE TABLE IF NOT EXISTS resolutions (
    ip TEXT, domain TEXT, ts REAL,
    PRIMARY KEY (ip, domain)
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    dedup_key   TEXT UNIQUE NOT NULL,
    detector    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,           -- low | medium | high | critical
    title       TEXT NOT NULL,
    device_ip   TEXT,                    -- the LAN device the alert is about
    peer        TEXT,                    -- the other side: IP or domain
    ts_first    REAL NOT NULL,
    ts_last     REAL NOT NULL,
    count       INTEGER DEFAULT 1,
    status      TEXT DEFAULT 'open',     -- open | acknowledged | resolved
    evidence    TEXT NOT NULL            -- JSON
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts_last);
CREATE INDEX IF NOT EXISTS alerts_dev ON alerts(device_ip);

CREATE TABLE IF NOT EXISTS explanations (
    alert_id    INTEGER PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
    provider    TEXT, model TEXT,
    summary     TEXT, why TEXT, risk TEXT,
    actions     TEXT,                    -- JSON list of strings
    latency_ms  INTEGER,
    created     REAL,
    stats       TEXT,                    -- JSON runner timing (Llama only)
    facts       TEXT                     -- JSON list: the grounded facts it was written from
);

-- M5: requested response actions. Recorded only; never executed.
CREATE TABLE IF NOT EXISTS action_requests (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, alert_id INTEGER, action TEXT,
    target TEXT, command_preview TEXT, status TEXT DEFAULT 'not_executed'
);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


# Columns added after the first release: (table, column, type)
_ADDED_COLUMNS = [("explanations", "stats", "TEXT"), ("explanations", "facts", "TEXT"),
                  ("alerts", "ts_raised", "REAL")]   # wall-clock time NetWatch raised (or re-raised) the alert


def _migrate(conn: sqlite3.Connection) -> None:
    for table, column, ctype in _ADDED_COLUMNS:
        cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ctype}")
            except sqlite3.OperationalError as e:   # another service added it first
                if "duplicate column" not in str(e):
                    raise
    conn.commit()


def get_meta(conn: sqlite3.Connection, key: str, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def set_meta(conn: sqlite3.Connection, key: str, value) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )


def prune(conn: sqlite3.Connection, before_ts: float) -> None:
    """Drop raw records older than the retention window; alerts are kept."""
    for table, col in (("flows", "ts_start"), ("dns", "ts"), ("tls", "ts"), ("http", "ts"), ("resolutions", "ts")):
        conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (before_ts,))
    conn.commit()
