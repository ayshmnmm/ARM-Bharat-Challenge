"""HTTP API + static dashboard. Bound to the wlan0 address or loopback only."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, actions, db, system
from .alerts import row_to_dict
from .config import Config, load
from .criteria import criteria
from .detectors.feeds import feed_status
from .explain import explain_alert
from .explain.facts import headline
from .ml import load_card

SEVERITIES = ("critical", "high", "medium", "low")


class StatusBody(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class ActionBody(BaseModel):
    action: str



class LoginBody(BaseModel):
    pin: str


SESSION_COOKIE = "nw_session"
_OPEN_PATHS = {"/api/login", "/api/health", "/api/auth"}


def _session_secret(cfg: Config) -> bytes:
    """Per-install random key (kept in the state directory, so restarts keep people logged in)."""
    import os
    path = cfg.home / "session.key"
    if not path.exists():
        path.write_bytes(os.urandom(32))
        path.chmod(0o600)
    return path.read_bytes()


def _session_token(cfg: Config) -> str:
    import hashlib
    import hmac
    # Changing the PIN invalidates every existing session.
    return hmac.new(_session_secret(cfg), b"netwatch:" + cfg.pin.encode(), hashlib.sha256).hexdigest()


def create_app(cfg: Config | None = None, eve_path: Path | None = None) -> FastAPI:
    cfg = cfg or load()
    app = FastAPI(title="NetWatch", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")

    def conn() -> sqlite3.Connection:
        return db.connect(cfg.db_path)

    # -- optional PIN (NETWATCH_PIN) -----------------------------------------------------------
    import hmac as _hmac
    import time as _time

    failures: list[float] = []

    @app.middleware("http")
    async def require_pin(request: Request, call_next):
        path = request.url.path
        if cfg.pin and path.startswith("/api/") and path not in _OPEN_PATHS:
            if not _hmac.compare_digest(request.cookies.get(SESSION_COOKIE, ""), _session_token(cfg)):
                return JSONResponse({"detail": "Enter the PIN to open NetWatch"}, status_code=401)
        return await call_next(request)

    @app.get("/api/auth")
    def auth_status(request: Request):
        ok = not cfg.pin or _hmac.compare_digest(request.cookies.get(SESSION_COOKIE, ""), _session_token(cfg))
        return {"pin_required": bool(cfg.pin), "logged_in": ok}

    @app.post("/api/login")
    def login(body: LoginBody, response: Response):
        if not cfg.pin:
            return {"ok": True}
        now = _time.monotonic()
        failures[:] = [t for t in failures if now - t < 60]
        if len(failures) >= 5:
            raise HTTPException(429, "Too many wrong PINs. Wait a minute and try again.")
        if not _hmac.compare_digest(body.pin.encode(), cfg.pin.encode()):
            failures.append(now)
            raise HTTPException(401, "Wrong PIN")
        response.set_cookie(SESSION_COOKIE, _session_token(cfg), max_age=30 * 86400, httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/api/logout")
    def logout(response: Response):
        response.delete_cookie(SESSION_COOKIE)
        return {"ok": True}

    def clock(c: sqlite3.Connection) -> float:
        return db.get_meta(c, "event_clock", 0.0) or 0.0

    def explanation(c: sqlite3.Connection, a: dict) -> dict:
        row = c.execute("SELECT * FROM explanations WHERE alert_id=?", (a["id"],)).fetchone()
        if not row:
            # Not explained yet (Llama takes about a minute): serve the instant rule-based text meanwhile.
            exp = explain_alert(a, Config(explainer="template", **{k: getattr(cfg, k) for k in ("router_ip",)}))
            return {"provider": "pending" if cfg.explainer == "llama" else exp.provider, "model": None,
                    "summary": exp.summary, "why": exp.why, "risk": exp.risk, "actions": exp.actions,
                    "latency_ms": 0, "stats": None, "facts": exp.facts, "pending": cfg.explainer == "llama"}
        d = dict(row)
        d["actions"] = json.loads(d["actions"] or "[]")
        d["stats"] = json.loads(d["stats"]) if d.get("stats") else None
        d["facts"] = json.loads(d["facts"]) if d.get("facts") else []
        d["pending"] = False
        return d

    def short_summary(c: sqlite3.Connection, a: dict) -> str:
        """One-paragraph plain summary for alert lists: the AI's text if written, else the rule-based one."""
        row = c.execute("SELECT summary FROM explanations WHERE alert_id=?", (a["id"],)).fetchone()
        if row:
            return row["summary"]
        from .explain.templates import explain as template_explain
        return template_explain(a).summary

    def ml_info() -> dict | None:
        card = load_card(cfg.ml_dir) if cfg.ml_enabled else None
        if not card:
            return None
        t = card["test"]
        return {"algorithm": card["algorithm"], "dataset": card["dataset"], "classes": card["classes"],
                "accuracy": t["accuracy"], "macro_f1": t["macro_f1"], "per_class": t["per_class"],
                "train_rows": card["train_rows"], "test_rows": card["test_rows"],
                "inference_us_per_flow": card["inference_us_per_flow"], "features": card["features"],
                "importance": card["permutation_importance"], "lab_eval": card.get("lab_eval"),
                "beyond_rules": card.get("beyond_rules"),
                "operating_point": card.get("operating_point")}

    def explained_stats(c: sqlite3.Connection) -> dict:
        """How many alerts the on-device model explained, and its typical speed on this Pi."""
        rows = c.execute("SELECT provider, latency_ms, stats FROM explanations").fetchall()
        llama = [r for r in rows if r["provider"].startswith("llama")]
        st = [json.loads(r["stats"]) for r in llama if r["stats"]]
        avg = lambda xs: round(sum(xs) / len(xs), 1) if xs else None  # noqa: E731
        return {
            "total": len(rows), "by_llama": len(llama),
            "avg_latency_s": avg([r["latency_ms"] / 1000 for r in llama]),
            "avg_decode_tps": avg([s["decode_token_per_sec"] for s in st if "decode_token_per_sec" in s]),
            "avg_prefill_tps": avg([s["prefill_token_per_sec"] for s in st if "prefill_token_per_sec" in s]),
        }

    def device_names(c: sqlite3.Connection) -> dict[str, dict]:
        return {r["ip"]: {"hostname": r["hostname"], "kind": r["kind"], "vendor": r["vendor"]}
                for r in c.execute("SELECT ip, hostname, kind, vendor FROM devices")}

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/api/overview")
    def overview():
        c = conn()
        now = clock(c)
        sev = {s: 0 for s in SEVERITIES}
        for r in c.execute("SELECT severity, COUNT(*) n FROM alerts WHERE status='open' GROUP BY severity"):
            sev[r["severity"]] = r["n"]
        series = [dict(r) for r in c.execute(
            """SELECT CAST(ts_start / 60 AS INTEGER) * 60 AS t, SUM(bytes_out) AS up, SUM(bytes_in) AS down,
                      COUNT(*) AS flows
               FROM flows WHERE ts_start >= ? GROUP BY t ORDER BY t""", (now - 3600,))]
        talkers = [dict(r) for r in c.execute(
            """SELECT ip, hostname, kind, bytes_up, bytes_down FROM devices
               ORDER BY bytes_up + bytes_down DESC LIMIT 5""")]
        recent = [row_to_dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY COALESCE(ts_raised, ts_last) DESC, id DESC LIMIT 6")]
        names = device_names(c)
        for a in recent:
            a["device"] = names.get(a["device_ip"])
            a["headline"] = headline({**a, "devices": names}, cfg.router_ip)
            a["summary"] = short_summary(c, {**a, "devices": names})
        return {
            "clock": now,
            "devices_total": c.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "devices_active": c.execute("SELECT COUNT(*) FROM devices WHERE last_seen >= ?", (now - 600,)).fetchone()[0],
            "alerts_open": sev,
            "alerts_total": c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "traffic": series,
            "top_talkers": talkers,
            "recent_alerts": recent,
            "feeds": {k: v for k, v in feed_status(cfg).items() if k != "feeds"},
            "explainer": cfg.explainer,
            "explainer_model": Path(cfg.llama_model).name if cfg.explainer == "llama" and cfg.llama_model else None,
            "flows_total": c.execute("SELECT COUNT(*) FROM flows").fetchone()[0],
            "dns_total": c.execute("SELECT COUNT(*) FROM dns").fetchone()[0],
            "explained": explained_stats(c),
            "ml": ml_info(),
            "ml_alerts": c.execute("SELECT COUNT(*) FROM alerts WHERE detector='ml'").fetchone()[0],
            "ml_confirmed": c.execute("SELECT COUNT(*) FROM alerts WHERE evidence LIKE '%\"ml\": {%'").fetchone()[0],
        }

    @app.get("/api/devices")
    def devices():
        c = conn()
        now = clock(c)
        open_alerts = {r["device_ip"]: dict(r) for r in c.execute(
            """SELECT device_ip, COUNT(*) n,
                      MAX(CASE severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END) worst
               FROM alerts WHERE status='open' GROUP BY device_ip""")}
        out = []
        for r in c.execute("SELECT * FROM devices ORDER BY last_seen DESC"):
            d = dict(r)
            a = open_alerts.get(d["ip"], {})
            d["active"] = d["last_seen"] >= now - 600
            d["open_alerts"] = a.get("n", 0)
            d["worst_severity"] = SEVERITIES[3 - a["worst"]] if a else None
            out.append(d)
        return out

    @app.get("/api/devices/{ip}")
    def device(ip: str):
        c = conn()
        row = c.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if not row:
            raise HTTPException(404, "unknown device")
        names = device_names(c)
        now = clock(c)
        # Destinations by volume, labelled with the name the device used to reach them.
        dests = []
        for r in c.execute(
            """SELECT dst_ip, dst_port, proto, COUNT(*) flows, SUM(bytes_out) up, SUM(bytes_in) down,
                      MAX(ts_end) last
               FROM flows WHERE src_ip=? GROUP BY dst_ip, dst_port, proto
               ORDER BY up + down DESC LIMIT 25""", (ip,)):
            d = dict(r)
            name = c.execute(
                "SELECT sni FROM tls WHERE src_ip=? AND dst_ip=? AND sni IS NOT NULL ORDER BY ts DESC LIMIT 1",
                (ip, d["dst_ip"])).fetchone()
            if not name:
                name = c.execute("SELECT domain AS sni FROM resolutions WHERE ip=? ORDER BY ts DESC LIMIT 1",
                                 (d["dst_ip"],)).fetchone()
            d["name"] = name["sni"] if name else None
            dests.append(d)
        return {
            "device": dict(row),
            "traffic": [dict(r) for r in c.execute(
                """SELECT CAST(ts_start / 60 AS INTEGER) * 60 AS t, SUM(bytes_out) AS up, SUM(bytes_in) AS down
                   FROM flows WHERE (src_ip=? OR dst_ip=?) AND ts_start >= ? GROUP BY t ORDER BY t""",
                (ip, ip, now - 3600))],
            "destinations": dests,
            "dns": [dict(r) for r in c.execute(
                "SELECT ts, rrname, rrtype, rcode FROM dns WHERE src_ip=? ORDER BY ts DESC LIMIT 50", (ip,))],
            "tls": [dict(r) for r in c.execute(
                """SELECT sni, transport, MAX(ts) AS last, COUNT(*) AS n, ja4 FROM tls WHERE src_ip=?
                   GROUP BY sni, transport ORDER BY last DESC LIMIT 50""", (ip,))],
            "fingerprints": [dict(r) for r in c.execute(
                """SELECT ja4, COUNT(*) AS n FROM tls WHERE src_ip=? AND ja4 IS NOT NULL
                   GROUP BY ja4 ORDER BY n DESC LIMIT 10""", (ip,))],
            "alerts": [{**a, "headline": headline({**a, "devices": names}, cfg.router_ip)} for a in (
                row_to_dict(r) for r in c.execute(
                    "SELECT * FROM alerts WHERE device_ip=? ORDER BY COALESCE(ts_raised, ts_last) DESC, id DESC LIMIT 50", (ip,)))],
        }

    @app.get("/api/alerts")
    def list_alerts(
        status: str | None = None,
        severity: str | None = None,
        device: str | None = None,
        kind: str | None = None,
        limit: int = Query(200, le=1000),
    ):
        c = conn()
        where, args = [], []
        for col, val in (("status", status), ("severity", severity), ("device_ip", device), ("kind", kind)):
            if val:
                where.append(f"{col}=?")
                args.append(val)
        sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "") + \
              " ORDER BY COALESCE(ts_raised, ts_last) DESC, id DESC LIMIT ?"
        names = device_names(c)
        out = []
        for r in c.execute(sql, (*args, limit)):
            a = row_to_dict(r)
            a["device"] = names.get(a["device_ip"])
            a["headline"] = headline({**a, "devices": names}, cfg.router_ip)
            a["summary"] = short_summary(c, {**a, "devices": names})
            a["explained"] = c.execute("SELECT 1 FROM explanations WHERE alert_id=?", (a["id"],)).fetchone() is not None
            out.append(a)
        return out

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: int):
        c = conn()
        row = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(404, "unknown alert")
        a = row_to_dict(row)
        names = device_names(c)
        a["device"] = names.get(a["device_ip"])
        a["devices"] = names
        a["headline"] = headline(a, cfg.router_ip)
        a["explanation"] = explanation(c, a)
        del a["devices"]
        a["criteria"] = criteria(a)
        a["actions"] = []
        for act in actions.available(a):
            target, cmd = actions.preview(c, a, act)
            a["actions"].append({"action": act, "label": actions.ACTIONS[act], "target": target,
                                 "command_preview": cmd})
        a["action_requests"] = [dict(r) for r in c.execute(
            "SELECT * FROM action_requests WHERE alert_id=? ORDER BY ts DESC", (alert_id,))]
        return a

    @app.post("/api/alerts/{alert_id}/status")
    def set_status(alert_id: int, body: StatusBody):
        c = conn()
        if c.execute("UPDATE alerts SET status=? WHERE id=?", (body.status, alert_id)).rowcount == 0:
            raise HTTPException(404, "unknown alert")
        c.commit()
        return {"id": alert_id, "status": body.status}

    @app.post("/api/alerts/{alert_id}/actions")
    def request_action(alert_id: int, body: ActionBody):
        c = conn()
        row = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(404, "unknown alert")
        try:
            return actions.request(c, row_to_dict(row), body.action)
        except KeyError:
            raise HTTPException(400, f"action not available: {body.action}")

    @app.get("/api/timeline")
    def timeline(limit: int = Query(200, le=1000)):
        c = conn()
        names = device_names(c)
        events = []
        for r in c.execute("SELECT * FROM alerts ORDER BY ts_last DESC LIMIT ?", (limit,)):
            a = row_to_dict(r)
            events.append({"ts": a["ts_first"], "type": "alert", "severity": a["severity"], "title": a["title"],
                           "device_ip": a["device_ip"], "alert_id": a["id"]})
        for r in c.execute("SELECT ip, first_seen FROM devices ORDER BY first_seen DESC LIMIT ?", (limit,)):
            n = names.get(r["ip"], {})
            events.append({"ts": r["first_seen"], "type": "device", "severity": None,
                           "title": f"New device seen: {n.get('hostname') or r['ip']} ({n.get('kind') or 'Unknown'})",
                           "device_ip": r["ip"], "alert_id": None})
        for r in c.execute("SELECT * FROM action_requests ORDER BY ts DESC LIMIT ?", (limit,)):
            events.append({"ts": r["ts"], "type": "action", "severity": None,
                           "title": f"Action requested (not executed): {actions.ACTIONS.get(r['action'], r['action'])} "
                                    f"on {r['target']}", "device_ip": None, "alert_id": r["alert_id"]})
        events.sort(key=lambda e: e["ts"], reverse=True)
        return events[:limit]

    # -- PS3 scam check ------------------------------------------------------------------
    # Slow writing (the Llama weekly summary) runs in the live service, which has the memory budget for
    # the model; the API only queues work. For development without the live service, NETWATCH_API_WRITER=1 runs the
    # same background jobs here.
    check_wake = threading.Event()
    if os.environ.get("NETWATCH_API_WRITER") == "1":
        def writer() -> None:
            from .pipeline import background_jobs
            c = db.connect(cfg.db_path)
            while True:
                check_wake.wait(10)
                check_wake.clear()
                try:
                    while background_jobs(c, cfg):
                        pass
                except Exception:  # noqa: BLE001
                    logging.getLogger(__name__).exception("background writer failed")

        threading.Thread(target=writer, daemon=True, name="writer").start()

    @app.get("/api/summary")
    def get_summary():
        c = conn()
        return {"summary": db.get_meta(c, "weekly_summary", None),
                "writing": bool(db.get_meta(c, "summary_requested", False))}

    @app.post("/api/summary")
    def request_summary():
        c = conn()
        db.set_meta(c, "summary_requested", True)
        c.commit()
        check_wake.set()
        return {"writing": True}

    @app.get("/api/system")
    def system_status():
        return system.snapshot(cfg, eve_path)

    @app.get("/api/feeds")
    def feeds():
        return feed_status(cfg)

    if cfg.web_dir.is_dir():
        app.mount("/", StaticFiles(directory=cfg.web_dir, html=True), name="web")

        @app.exception_handler(404)
        async def spa_404(request, exc):
            if request.url.path.startswith("/api/"):
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": getattr(exc, "detail", "Not Found")}, status_code=404)
            page = cfg.web_dir / "404.html"
            return FileResponse(page, status_code=404) if page.exists() else FileResponse(cfg.web_dir / "index.html")

    return app
