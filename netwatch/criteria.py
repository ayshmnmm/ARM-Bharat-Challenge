"""Why an alert fired: each detector rule as "what was checked / what we saw / the rule".

Built from the detectors' own thresholds, so the dashboard can never disagree with the code that
raised the alert. Shown on the alert page under "Why NetWatch flagged this".
"""

from __future__ import annotations

from .detectors import WINDOW_S
from .detectors.scan import (
    BRUTE_HIGH_CONNS, BRUTE_MIN_CONNS, FLOOD_MIN_SYNS, PORT_SCAN_HIGH_PORTS, PORT_SCAN_MIN_PORTS, SWEEP_MIN_HOSTS,
)

CATEGORY = {"phishing": "phishing", "scam": "scam", "malware": "malware", "c2": "malware control (C2)",
            "lab": "lab test"}


def _c(check: str, observed, rule: str, met: bool = True) -> dict:
    return {"check": check, "observed": str(observed), "rule": rule, "met": met}


def _ml_rows(ml: dict, alone: bool) -> list[dict]:
    from .detectors.ml import ML_MIN_FLOWS, ML_MIN_PROB

    rows = [
        _c(f"Connections the AI detector judged as {ml['family_plain'].split(' (')[0]}",
           f"{ml['flows_flagged']} of {ml['flows_from_source']}",
           f"each at {round(ML_MIN_PROB * 100)}%+ confidence; alert at {ML_MIN_FLOWS}+ {f'within {WINDOW_S} s'}"),
        _c("Average confidence", f"{round(ml['confidence'] * 100)}%", "gradient-boosted trees, CIC-IDS2017"),
    ]
    if not alone:
        rows[0]["check"] = "Independent AI detector also flagged it: " + rows[0]["check"][0].lower() + rows[0]["check"][1:]
        rows.append(_c("AI and rules agree on the kind of attack", "yes" if ml.get("agrees") else "no",
                       "two independent methods", met=bool(ml.get("agrees"))))
    return rows


def criteria(alert: dict) -> list[dict]:
    rows = _criteria(alert)
    e = alert.get("evidence") or {}
    if "ml" in e and not alert["kind"].startswith("ml_"):
        rows += _ml_rows(e["ml"], alone=False)
    return rows


def _criteria(alert: dict) -> list[dict]:
    e, kind = alert.get("evidence") or {}, alert["kind"]
    if kind.startswith("ml_"):
        return _ml_rows(e, alone=True)
    window = f"within {WINDOW_S} s"
    if kind == "port_scan":
        n = e.get("ports_probed", 0)
        return [
            _c(f"Different ports probed on one device {window}", n,
               f"alert at {PORT_SCAN_MIN_PORTS}+, high at {PORT_SCAN_HIGH_PORTS}+"),
            _c("Probes looked like scanning (no data sent)", e.get("technique", "yes"), "connection attempts only"),
            _c("Services found answering", ", ".join(map(str, e.get("open_ports") or [])) or "none",
               "reported, not required", met=bool(e.get("open_ports"))),
        ]
    if kind == "host_sweep":
        return [_c(f"Different devices probed by one source {window}", e.get("hosts_probed", 0),
                   f"alert at {SWEEP_MIN_HOSTS}+")]
    if kind == "syn_flood":
        ports = e.get("ports") or []
        return [
            _c(f"Half-open connection requests to one device {window}", e.get("syn_count", 0),
               f"alert at {FLOOD_MIN_SYNS}+"),
            _c("Ports targeted", ", ".join(map(str, ports)), "3 or fewer (a flood, not a scan)", met=len(ports) <= 3),
        ]
    if kind == "brute_force":
        return [
            _c(f"Login sessions to {e.get('service', 'a login service')} (port {e.get('port')}) {window}",
               e.get("connections", 0), f"alert at {BRUTE_MIN_CONNS}+, high at {BRUTE_HIGH_CONNS}+"),
            _c("Each session sent data (a real login attempt)", f"{e.get('avg_bytes_sent', 0)} bytes on average",
               "more than 300 bytes"),
        ]
    if kind == "dga":
        from .detectors.behaviour import DGA_MIN_NX, DGA_MIN_RANDOM_SHARE
        return [_c(f"Non-existent names looked up {window}", e.get("nxdomain_names"), f"alert at {DGA_MIN_NX}+"),
                _c("Share that look random", f"{round(e.get('random_share', 0) * 100)}%",
                   f"at least {round(DGA_MIN_RANDOM_SHARE * 100)}%")]
    if kind == "dns_tunnel":
        from .detectors.behaviour import TUNNEL_MIN_LABEL, TUNNEL_MIN_NAMES
        return [_c(f"Different names under {e.get('domain')} {window}", e.get("distinct_names"), f"alert at {TUNNEL_MIN_NAMES}+"),
                _c("Average length of the hidden part", f"{e.get('avg_name_length')} characters", f"at least {TUNNEL_MIN_LABEL}"),
                _c("Randomness (entropy)", f"{e.get('avg_entropy')} bits per character", "at least 3.5")]
    if kind == "beaconing":
        from .detectors.behaviour import BEACON_MAX_JITTER, BEACON_MIN_CONNS
        return [_c("Connections to the same internet address and port", e.get("check_ins"), f"at least {BEACON_MIN_CONNS} in 30 min"),
                _c("Time between them", f"{e.get('period_s')} s", "between 10 s and 15 min"),
                _c("How regular (spread / average gap)", e.get("jitter"), f"at most {BEACON_MAX_JITTER}"),
                _c("Data sent each time", f"{e.get('median_bytes_sent')} bytes", "small: a check-in, not a download")]
    if kind == "new_fingerprint":
        return [_c("Encrypted-connection fingerprint (JA4)", e.get("ja4"), "never seen on this device or network"),
                _c("Device known for", "more than a day", "learning period over")]
    if kind in ("unusual_upload", "unusual_destinations"):
        from .detectors.baseline import Z_ALERT
        return [_c("This minute", e.get("this_minute"), f"usual {e.get('usual_per_minute')} ± {e.get('usual_spread')}"),
                _c("Distance from this device's normal", f"{e.get('z_score')} spreads", f"alert at {Z_ALERT}+"),
                _c("Minutes of normal behaviour learned", e.get("minutes_learned"), "120+ before alerting")]
    if kind.endswith("_domain") or kind == "c2_ip":
        feeds = ", ".join(f.get("name", "?") for f in e.get("feeds") or []) or "threat list"
        cat = CATEGORY.get(e.get("category", ""), e.get("category", "listed"))
        rows = [
            _c("Address is on a threat list", e.get("indicator"), f"{feeds} ({cat})"),
            _c("Seen in", ", ".join(e.get("seen_via") or []) or "traffic", "DNS, HTTPS name (SNI), web or IP"),
            _c("Device actually connected", "yes" if e.get("connected") else "no (only looked up)",
               "raises the severity", met=bool(e.get("connected"))),
        ]
        if e.get("confidence") == "low":
            rows.append(_c("Match confidence", "low: shared platform", "severity lowered", met=False))
        return rows
    return []
