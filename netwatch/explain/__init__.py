"""Alert explanations in plain English.

Providers:
  template - deterministic, instant; always available and used as the fallback
  llama    - Llama 3.2 1B Instruct running on the Pi CPU through ExecuTorch (see explain/llama.py)
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field

from ..alerts import row_to_dict
from ..config import Config


@dataclass
class Explanation:
    summary: str
    why: str
    risk: str
    actions: list[str]
    provider: str
    model: str | None = None
    latency_ms: int = 0
    stats: dict = field(default_factory=dict)  # runner timing: prefill/decode tokens per second etc.
    facts: list[str] = field(default_factory=list)  # the grounded facts the explanation was written from


def explain_alert(alert: dict, cfg: Config) -> Explanation:
    from .facts import facts
    from .templates import explain as template_explain

    if cfg.explainer == "llama":
        from .llama import LlamaExplainer

        try:
            return LlamaExplainer.get(cfg).explain(alert)
        except Exception as e:  # model missing, runner crash, timeout, unparseable output
            exp = template_explain(alert)
            exp.provider = f"template (llama failed: {type(e).__name__})"
            exp.facts = facts(alert, cfg.router_ip)
            return exp
    exp = template_explain(alert)
    exp.facts = facts(alert, cfg.router_ip)
    return exp


def with_devices(conn: sqlite3.Connection, alert: dict) -> dict:
    """Attach device names so explanations can say "the device \"kids-laptop\"" instead of a bare IP."""
    alert["devices"] = {r["ip"]: dict(r) for r in conn.execute("SELECT ip, hostname, kind, vendor FROM devices")}
    alert["device"] = alert["devices"].get(alert.get("device_ip"))
    return alert


def explain_pending(conn: sqlite3.Connection, cfg: Config, limit: int = 1) -> int:
    """Explain the most severe unexplained alerts first. Small `limit` keeps the CPU free for routing."""
    rows = conn.execute(
        """SELECT a.* FROM alerts a LEFT JOIN explanations e ON e.alert_id = a.id
           WHERE e.alert_id IS NULL
           ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                    a.ts_last DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    for row in rows:
        alert = with_devices(conn, row_to_dict(row))
        t = time.monotonic()
        exp = explain_alert(alert, cfg)
        exp.latency_ms = exp.latency_ms or int((time.monotonic() - t) * 1000)
        # Llama takes ~1 min; if the alert's severity was raised meanwhile, this explanation is stale: drop it.
        conn.execute(
            """INSERT OR REPLACE INTO explanations(alert_id, provider, model, summary, why, risk, actions, latency_ms,
                                                  created, stats, facts)
               SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM alerts WHERE id = ? AND severity = ?)""",
            (alert["id"], exp.provider, exp.model, exp.summary, exp.why, exp.risk, json.dumps(exp.actions),
             exp.latency_ms, time.time(), json.dumps(exp.stats) if exp.stats else None,
             json.dumps(exp.facts), alert["id"], alert["severity"]),
        )
        conn.commit()
    return len(rows)
