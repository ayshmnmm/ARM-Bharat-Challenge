"""M5 response actions: DRY RUN ONLY.

Each action returns the exact command it *would* run and records the request. Nothing here
executes anything: the router's firewall must not be changed. If enforcement is
ever enabled it would live in its own `inet netwatch` nft table, limited to wlan0 traffic.
"""

from __future__ import annotations

import ipaddress
import sqlite3
import time

ACTIONS = {
    "quarantine_device": "Quarantine device",
    "block_domain": "Block domain",
    "block_ip": "Block IP address",
    "trust_device": "Mark device as trusted",
    "snooze": "Snooze similar alerts for 24 h",
}


def _resolved_ips(conn: sqlite3.Connection, domain: str) -> list[str]:
    return [r["ip"] for r in conn.execute(
        "SELECT ip FROM resolutions WHERE domain = ? OR domain LIKE ? LIMIT 20", (domain, f"%.{domain}"))]


def available(alert: dict) -> list[str]:
    acts = []
    if alert.get("device_ip"):
        acts += ["quarantine_device", "trust_device"]
    if alert["kind"].endswith("_domain"):
        acts.append("block_domain")
    peer = alert.get("peer")
    try:
        if peer and ipaddress.ip_address(peer).is_global:  # never offer to block the router or a LAN device
            acts.append("block_ip")
    except ValueError:
        pass  # peer is a domain
    acts.append("snooze")
    return acts


def preview(conn: sqlite3.Connection, alert: dict, action: str) -> tuple[str, str]:
    """(target, command) for an action. The command is shown to the user, never executed."""
    dev = alert.get("device_ip")
    peer = alert.get("peer")
    if action == "quarantine_device":
        return dev, (f'nft add rule inet netwatch forward iifname "wlan0" ip saddr {dev} drop\n'
                     f'nft add rule inet netwatch forward oifname "wlan0" ip daddr {dev} drop')
    if action == "block_domain":
        ips = _resolved_ips(conn, peer) or ["<addresses resolved for this domain>"]
        return peer, (f"# DNS answers for {peer} are refused and its current addresses dropped\n"
                      f"nft add element inet netwatch blocked_v4 {{ {', '.join(ips)} }}")
    if action == "block_ip":
        return peer, f"nft add element inet netwatch blocked_v4 {{ {peer} }}"
    if action == "trust_device":
        return dev, f"# NetWatch database only: mark {dev} as trusted (lower alert severity for scans it runs)"
    if action == "snooze":
        return f"{alert['kind']} / {dev}", f"# NetWatch database only: mute '{alert['kind']}' alerts for {dev} for 24 hours"
    raise KeyError(action)


def request(conn: sqlite3.Connection, alert: dict, action: str) -> dict:
    if action not in available(alert):
        raise KeyError(action)
    target, command = preview(conn, alert, action)
    cur = conn.execute(
        "INSERT INTO action_requests(ts, alert_id, action, target, command_preview) VALUES(?,?,?,?,?)",
        (time.time(), alert["id"], action, target, command),
    )
    conn.commit()
    return {"id": cur.lastrowid, "action": action, "label": ACTIONS[action], "target": target,
            "command_preview": command, "status": "not_executed",
            "message": "Recorded only. Response actions are disabled in this build; nothing was changed."}

