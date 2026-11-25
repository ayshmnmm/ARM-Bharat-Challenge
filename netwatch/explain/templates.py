"""Rule-based parts of every explanation: the risk statement and the next steps (decided by rules,
never by the language model), plus an instant plain-English fallback summary built from the same
grounded facts the model gets. Written for people with no technical background.
"""

from __future__ import annotations

import re

from . import Explanation
from .facts import BACKGROUND, facts, who


def _sentence(line: str) -> str:
    text = line.split(": ", 1)[1] if ": " in line else line
    text = text[0].upper() + text[1:]
    return text if text.endswith(".") else text + "."


def _fallback_text(alert: dict) -> tuple[str, str]:
    """Summary = what NetWatch saw; why = the background line. Same facts as the AI is given."""
    lines = facts(alert)
    saw = next((ln for ln in lines if ln.startswith("What NetWatch saw:")), alert["title"])
    bg = next((ln for ln in lines if ln.startswith("Background:")), "")
    saw = re.sub(r", made by [^)]*\)", ")", saw)  # keep the quick summary short; the AI gets the maker
    return _sentence(saw), (_sentence(bg) if bg else "Flagged by the rules as unusual.")


def _risk_and_actions(a: dict) -> tuple[str, list[str]]:
    e, kind, sev = a.get("evidence") or {}, a["kind"], a["severity"]
    W = lambda ip: who(ip, a)  # noqa: E731
    src = e.get("source") or (e.get("sample_sources") or [None])[0]
    inside = bool(a.get("device_ip")) and a.get("device_ip") == src

    if kind in ("port_scan", "host_sweep", "ml_scan"):
        return (
            ("A device on your own Wi-Fi is exploring your network. Either someone is testing on purpose, "
             "or the device has been taken over." if inside else
             "Something outside is looking for a way into your network."),
            [f"Ask whoever uses {W(src)} if they ran a network tool on purpose.",
             "If nobody did, disconnect that device from the Wi-Fi and run a virus scan on it.",
             "Turn off services you do not use on the scanned device, and keep it updated."],
        )
    if kind in ("syn_flood", "ml_dos"):
        return (
            "The targeted device or service may slow down or stop working while this continues.",
            [f"Find the device sending the traffic ({W(src) if src else 'see the evidence'}) and switch it off "
             "or disconnect it.",
             "If it keeps happening, block that device at the router.",
             "Check that the targeted device works normally again."],
        )
    if kind in ("brute_force", "ml_brute_force"):
        return (
            f"If the password is weak, an attacker could take control of {W(e.get('target') or a.get('peer'))}.",
            ["Change that device's password to a long, unique one.",
             f"Ask whoever uses {W(src)} if they were logging in themselves.",
             "If not, disconnect that device from the Wi-Fi and run a virus scan on it."],
        )
    if kind == "ml_web_attack":
        return (
            "A website or web admin page on your network may be under attack, which could let someone in.",
            ["Update the targeted device's software and change its admin password.",
             f"Check {W(src)}: if nobody on it was testing a website, disconnect it.",
             "If this was expected security testing, mark the device as trusted."],
        )
    if kind == "ml_botnet":
        return (
            "The device may be infected and controlled by someone else, who can use it to attack others.",
            [f"Disconnect {W(src)} from the Wi-Fi.",
             "Run a virus scan, or reset the device to factory settings.",
             "Change passwords that were used on it, from a different device."],
        )
    if kind in ("dga", "dns_tunnel"):
        return (
            "The device is probably infected with malware" + (" that may be copying your data out." if kind == "dns_tunnel"
                                                                else " that is looking for its control server."),
            [f"Disconnect {W(src)} from the Wi-Fi.",
             "Run a full virus scan, or reset the device to factory settings.",
             "Change passwords that were used on it, from a different device."],
        )
    if kind == "beaconing":
        return (
            "If this device is not supposed to talk to that server, it may be infected and waiting for orders.",
            [f"Check what {W(src)} is. Smart plugs, cameras and TVs often check in with their maker; if this "
             "server is the maker's, mark the device as trusted.",
             "If the server is unknown, disconnect the device and update or reset it."],
        )
    if kind == "new_fingerprint":
        return (
            "Usually a newly installed or updated app, but unwanted software looks the same.",
            [f"Ask whoever uses {W(src)} if they installed or updated an app recently.",
             "If nobody did, run a virus scan on the device."],
        )
    if kind == "unusual_destinations":
        return (
            "This is unusual for this device. It may be a new app or a network tool someone ran, or the device "
            "may have been taken over and be scanning.",
            [f"Ask whoever uses {W(src)} if they ran a network or scanning tool.",
             "If not, disconnect the device and check it for malware.",
             "If this is normal for the device now, mark it as trusted."],
        )
    if kind == "unusual_upload":
        return (
            "This is unusual for this device. It may be a backup or a big upload someone started, or the device "
            "may have been taken over.",
            [f"Ask whoever uses {W(src)} if they were uploading or syncing something large.",
             "If not, disconnect the device and check it for malware.",
             "If this is normal for the device now, mark it as trusted."],
        )
    if kind.endswith("_domain") or kind == "c2_ip":
        cat = e.get("category", "phishing")
        if cat == "lab":
            return ("No danger: test address.", ["Nothing to do."])
        if cat == "c2":
            return ("Talking to a malware control server usually means the device is already infected.",
                    ["Disconnect the device from the Wi-Fi now.", "Run a virus scan, or reset the device.",
                     "Change passwords used on it, from a different device."])
        if cat == "malware":
            return ("The device may have downloaded harmful software.",
                    ["Delete anything unexpected that was recently downloaded on the device.",
                     "Run a virus scan.", "Block this site at the router."])
        return (
            ("If a password, OTP or card number was typed on that page, assume someone else now has it."
             if e.get("connected") else
             "The device looked up the site. It may not have opened it yet, but someone clicked or tapped a link."),
            ["Ask the device's user whether they opened a link from an SMS, email or WhatsApp message.",
             "If they typed any password, OTP or card details, change them and call the bank now.",
             "Block this site at the router."],
        )
    return ("Rated " + sev + " by the rules.", ["Check the details below."])


def explain(alert: dict) -> Explanation:
    try:
        summary, why = _fallback_text(alert)
        risk, actions = _risk_and_actions(alert)
    except (KeyError, TypeError, IndexError, ValueError):
        summary, why = alert["title"] + ".", "Flagged by the rules."
        risk, actions = f"Rated {alert['severity']} by the rules.", ["Check the details below."]
    actions = [re.sub(r", made by [^)]*\)", ")", a) for a in actions]  # steps stay short
    return Explanation(summary=summary, why=why, risk=risk, actions=actions, provider="template")


__all__ = ["explain", "BACKGROUND"]
