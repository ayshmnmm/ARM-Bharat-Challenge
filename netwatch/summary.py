"""A plain-English summary of the past week on the network, written by Llama from counted facts."""

from __future__ import annotations

import re
import sqlite3
import time
from collections import Counter

from . import db
from .config import Config
from .explain.facts import KIND_PHRASE

KIND_PLAIN = {
    "port_scan": "port scans", "host_sweep": "network sweeps", "syn_flood": "connection floods",
    "brute_force": "password-guessing attempts", "dga": "malware-style address look-ups",
    "dns_tunnel": "data hidden in DNS", "beaconing": "regular check-ins to an internet server",
    "new_fingerprint": "new software", "unusual_upload": "unusual uploads", "unusual_destinations": "unusual activity",
    "phishing_domain": "phishing sites", "scam_domain": "scam sites", "malware_domain": "malware sites",
    "c2_domain": "malware control servers", "c2_ip": "malware control servers", "lab_domain": "test phishing sites",
}


def facts(conn: sqlite3.Connection, cfg: Config, days: int = 7) -> list[str]:
    now = db.get_meta(conn, "event_clock", 0.0) or time.time()
    since = now - days * 86400
    lines = [f"Period: the last {days} days"]
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    new = conn.execute("SELECT kind FROM devices WHERE first_seen >= ?", (since,)).fetchall()
    lines.append(f"Devices that used the Wi-Fi: {total}")
    lines.append(f"Devices seen for the first time this week: {len(new)}")
    if new:
        kinds = Counter(KIND_PHRASE.get((r["kind"] or "").replace(" (private MAC)", ""), "unknown device") for r in new)
        lines.append("What kind of devices the new ones are: " + ", ".join(f"{k} x{n}" for k, n in kinds.most_common(4)))
    alerts = conn.execute("SELECT kind, severity, status, detector, evidence FROM alerts WHERE ts_last >= ?",
                          (since,)).fetchall()
    if not alerts:
        lines.append("Alerts: none this week")
    else:
        by_kind = Counter(KIND_PLAIN.get(a["kind"], a["kind"].replace("_", " ")) for a in alerts)
        lines.append(f"Alerts: {len(alerts)} in total: " + ", ".join(f"{n} {k}" for k, n in by_kind.most_common(5)))
        urgent = sum(a["severity"] in ("high", "critical") for a in alerts)
        still_open = sum(a["status"] == "open" for a in alerts)
        lines.append(f"Alerts rated urgent or worse: {urgent}")
        lines.append(f"Alerts nobody has looked at yet: {still_open}")
        confirmed = sum('"ml": {' in a["evidence"] for a in alerts)
        if confirmed:
            lines.append(f"Alerts that the AI detector independently agreed with: {confirmed}")
    busiest = conn.execute(
        "SELECT ip, hostname, kind, bytes_up + bytes_down AS b FROM devices ORDER BY b DESC LIMIT 1").fetchone()
    if busiest and busiest["b"]:
        name = busiest["hostname"] or KIND_PHRASE.get((busiest["kind"] or "").replace(" (private MAC)", ""), "a device")
        lines.append(f"Busiest device: {name} ({busiest['ip']}), {busiest['b'] / 1e9:.1f} GB in total")
    return lines


def write(conn: sqlite3.Connection, cfg: Config, days: int = 7) -> dict:
    lines = facts(conn, cfg, days)
    out = {"ts": time.time(), "days": days, "facts": lines, "provider": "rules", "latency_ms": 0}
    if cfg.explainer == "llama":
        from .explain.llama import LlamaExplainer
        try:
            # A 1B model miscounts in number-heavy text (tested: it copied "2 new" from the worked example
            # and merged two counts). So the counts are written by NetWatch, and Llama writes only the
            # advice, which must contain no numbers at all.
            _what, why, stats, ms = LlamaExplainer.get(cfg).write(_qualitative(conn, days), task="summary")
            if re.search(r"\d", why):
                raise ValueError("summary advice contains numbers")
            out.update(why=why, provider="llama-executorch", latency_ms=ms, stats=stats)
        except Exception as e:  # noqa: BLE001
            out["provider"] = f"rules (llama failed: {type(e).__name__})"
    what, why = _fallback(conn, days)
    out["what"] = what
    out.setdefault("why", why)
    db.set_meta(conn, "weekly_summary", out)
    conn.commit()
    return out


def _count(n: int, phrase: str) -> str:
    """"1 port scan", "2 port scans"."""
    if n == 1 and phrase.endswith("s") and not phrase.endswith(("DNS", "ss")):
        phrase = phrase[:-1]
    return f"{n} {phrase}"


def _fallback(conn: sqlite3.Connection, days: int) -> tuple[str, str]:
    now = db.get_meta(conn, "event_clock", 0.0) or time.time()
    since = now - days * 86400
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    new = conn.execute("SELECT COUNT(*) FROM devices WHERE first_seen >= ?", (since,)).fetchone()[0]
    alerts = conn.execute("SELECT kind, severity, status FROM alerts WHERE ts_last >= ?", (since,)).fetchall()
    what = f"{total} device{'s' if total != 1 else ''} used your Wi-Fi this week" + (f", {new} of them new." if new else ".")
    if not alerts:
        return what, "Nothing suspicious was seen this week."
    kinds = Counter(KIND_PLAIN.get(a["kind"], a["kind"].replace("_", " ")) for a in alerts)
    what += f" NetWatch raised {len(alerts)} alert{'s' if len(alerts) != 1 else ''}: " + \
        ", ".join(_count(n, k) for k, n in kinds.most_common(3)) + "."
    still = sum(a["status"] == "open" for a in alerts)
    why = (f"{still} still need{'s' if still == 1 else ''} a look. Open them from the home page to see what to do."
           if still else "All of them have been looked at.")
    return what, why


def _qualitative(conn: sqlite3.Connection, days: int) -> list[str]:
    """The week's facts without any numbers, for the advice sentence (a 1B model mangles counts)."""
    now = db.get_meta(conn, "event_clock", 0.0) or time.time()
    since = now - days * 86400
    alerts = conn.execute("SELECT kind, severity, status FROM alerts WHERE ts_last >= ?", (since,)).fetchall()
    new = conn.execute("SELECT COUNT(*) FROM devices WHERE first_seen >= ?", (since,)).fetchone()[0]
    lines = ["Period: this week"]
    lines.append("New devices joined the Wi-Fi this week" if new else "No new devices joined the Wi-Fi this week")
    if not alerts:
        lines.append("There were no alerts this week")
    else:
        kinds = sorted({KIND_PLAIN.get(a["kind"], a["kind"].replace("_", " ")) for a in alerts})
        lines.append("Kinds of alerts this week: " + ", ".join(kinds))
        if any(a["severity"] in ("high", "critical") for a in alerts):
            lines.append("Some alerts were rated urgent")
        if any(a["status"] == "open" for a in alerts):
            lines.append("Some alerts have not been looked at yet")
        else:
            lines.append("Every alert has been looked at")
    return lines
