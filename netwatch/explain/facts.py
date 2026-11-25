"""Grounded facts for an alert, in plain words: the only material the on-device model may use.

Each alert becomes a short list of "label: value" lines built from the detector's evidence, the
device table (names, makers) and the ML model's verdict. Llama writes its own explanation from
these lines; every address and number it uses must appear here, which the output checks enforce.
The same lines are shown on the alert page ("What the AI was told"), so the explanation can be
checked against its sources.
"""

from __future__ import annotations

PORT_NAMES = {
    20: "file transfer (FTP)", 21: "file transfer (FTP)", 22: "remote login (SSH)", 23: "remote login (Telnet)",
    25: "email sending (SMTP)", 53: "name lookups (DNS)", 80: "web pages (HTTP)", 110: "email (POP3)",
    123: "time sync (NTP)", 139: "Windows file sharing", 143: "email (IMAP)", 443: "secure web pages (HTTPS)",
    445: "Windows file sharing (SMB)", 554: "camera video streams (RTSP)", 1883: "smart-home messages (MQTT)",
    3000: "a web app", 3306: "a database (MySQL)", 3389: "remote desktop (RDP)", 5432: "a database (PostgreSQL)",
    5900: "screen sharing (VNC)", 8000: "a web app", 8080: "a web admin page", 8443: "a secure web admin page",
    8888: "a web app",
}

BACKGROUND = {
    "port_scan": "A port scan checks which services on a device answer, like trying every door of a building "
                 "to see which are unlocked. It is usually the first step before an attack.",
    "host_sweep": "A sweep contacts many devices one after another to find out what is on the network. "
                  "Worms and attackers do this to choose their next target.",
    "syn_flood": "A SYN flood starts huge numbers of connections and never finishes them, so the target runs out "
                 "of room for real users. It is a denial-of-service attack.",
    "brute_force": "Many quick logins in a row usually mean a program is guessing passwords one after another.",
    "phishing": "A phishing site is a fake page made to steal passwords, OTPs or card details.",
    "scam": "A scam site tricks people into paying or sharing personal details.",
    "malware": "A malware site spreads harmful software.",
    "c2": "A command-and-control server sends orders to devices that are already infected with malware.",
    "lab": "This is a reserved test address on the phishing list. It is not a real threat.",
    "dga": "Some malware tries hundreds of random-looking web addresses until it finds the one its owner has "
           "registered, to get its instructions. Normal apps look up real, existing names.",
    "dns_tunnel": "Address look-ups (DNS) are rarely blocked, so malware can hide stolen data inside very long, "
                  "random-looking names and send it out that way.",
    "beaconing": "Malware on an infected device often 'phones home' on a fixed clock to ask for orders. Some normal "
                 "smart-home devices also check in regularly, so this needs a human look.",
    "new_fingerprint": "Every app makes encrypted connections in its own recognisable way. A pattern never seen before "
                       "on this network means new software is running on the device, such as a new app or something unwanted.",
    "unusual_upload": "A large upload far above this device's usual can mean files are being copied off it, "
                      "or that it is being used in an attack.",
    "unusual_destinations": "A sudden jump far above this device's usual can mean it was taken over and is "
                            "scanning or spreading.",
    "ml_dos": "Flooding traffic tries to overload a device or service so that it stops working for everyone.",
    "ml_scan": "Scanning probes a device or network for open services, usually before an attack.",
    "ml_brute_force": "Repeated logins usually mean a program is guessing passwords.",
    "ml_web_attack": "Web attacks send malicious requests to a website or web admin page to break in or steal data.",
    "ml_botnet": "Botnet traffic comes from a device that is remotely controlled by criminals.",
}


def port_name(port) -> str:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return str(port)
    return f"port {p}, {PORT_NAMES[p]}" if p in PORT_NAMES else f"port {p}"


KIND_PHRASE = {
    "Laptop / PC": "laptop", "Phone / tablet": "phone", "Phone": "phone", "Windows PC": "Windows computer",
    "Mac": "Mac", "Apple device": "Apple device", "IoT device": "smart-home device", "Media / TV": "TV or media player",
    "Raspberry Pi": "Raspberry Pi", "Virtual machine": "virtual machine",
}


def _kind_phrase(info: dict | None) -> str | None:
    kind = ((info or {}).get("kind") or "").replace(" (private MAC)", "").strip()
    return KIND_PHRASE.get(kind)


def device_label(info: dict | None) -> str | None:
    """Same naming as the dashboard: hostname, else the device type, else nothing."""
    if not info:
        return None
    name = info.get("hostname") or (info.get("kind") or "").replace(" (private MAC)", "").strip()
    if not name or name.lower() == "unknown":
        return None
    return name


def who(ip: str | None, alert: dict, cfg_router: str = "192.168.1.1") -> str:
    """A person-friendly name for an address, always with the address itself."""
    if not ip:
        return "an unknown device"
    if ip == cfg_router:
        return f"your router ({ip})"
    names = alert.get("devices") or {}
    info = names.get(ip) or (alert.get("device") if ip == alert.get("device_ip") else None)
    maker = (info or {}).get("vendor") or ""
    real_maker = maker and not any(w in maker.lower() for w in ("private", "random", "unknown"))
    if info and not info.get("hostname") and _kind_phrase(info):
        extra = f", made by {maker}" if real_maker else ""
        return f"a {_kind_phrase(info)} on your Wi-Fi ({ip}{extra})"
    label = device_label(info)
    if label:
        extra = f", made by {maker}" if real_maker and maker.lower() not in label.lower() else ""
        return f'the device "{label}" ({ip}{extra})'
    if ip.startswith(("192.168.", "10.")) or ip.startswith("172."):
        return f"a device on your Wi-Fi ({ip})"
    return f"{ip}, an address on the internet"


def _num(x) -> str:
    if isinstance(x, float):
        if x >= 100:
            return f"{x:.0f}"
        if 0 < x < 1:
            return f"{x:.2f}".rstrip("0").rstrip(".") if x >= 0.01 else "0.01"
        return f"{x:.1f}".rstrip("0").rstrip(".")
    return str(x)


def _seconds(x) -> str:
    """Durations as people say them; tiny ones as "under a second" (no number to misread)."""
    x = float(x or 0)
    return "in under a second" if x < 1 else f"in {_num(x)} seconds"


def _ports(ports, limit: int = 5) -> str:
    ports = list(ports or [])
    if not ports:
        return "none"
    shown = "; ".join(port_name(p) for p in ports[:limit])
    return shown + (f"; and {len(ports) - limit} more" if len(ports) > limit else "")


def _ml_lines(ml: dict, alone: bool) -> list[str]:
    pct = round(ml["confidence"] * 100)
    if not alone:
        # Second opinion on a rule alert: one line, to keep the prompt short.
        return [f"Second opinion: NetWatch's AI detector independently judged {ml['flows_flagged']} connections "
                f"from {ml['source']} as {ml['family_plain'].split(' (')[0]} ({pct}% confidence), "
                + ("agreeing with the rules" if ml.get("agrees") else "a different kind of attack than the rules found")]
    lines = [
        f"AI detector verdict: {ml['flows_flagged']} of {ml['flows_from_source']} connections from "
        f"{ml['source']} look like {ml['family_plain']} ({pct}% confidence)",
    ]
    saw = []
    for s in ml.get("what_the_model_saw", []):
        # the port is listed separately; a feature that looks just like normal traffic explains nothing
        if s["feature"] == "dst_port" or _num(s["flagged_median"]) == _num(s["normal_median"]):
            continue
        saw.append(f"{s['plain']} {_num(s['flagged_median'])} (normal traffic: {_num(s['normal_median'])})")
    saw = saw[:2]
    if saw:
        lines.append("What stood out to the AI detector: " + "; ".join(saw))
    return lines


def facts(alert: dict, router_ip: str = "192.168.1.1") -> list[str]:
    try:
        return _facts(alert, router_ip)
    except (KeyError, IndexError, TypeError, ValueError):
        # Evidence from an older version or an unexpected shape: say only what is certain.
        return [f"What NetWatch saw: {alert['title']}", f"Seriousness set by NetWatch: {alert['severity']}"]


def _facts(alert: dict, router_ip: str) -> list[str]:
    e = alert.get("evidence") or {}
    kind = alert["kind"]
    W = lambda ip: who(ip, alert, router_ip)  # noqa: E731
    lines: list[str] = []
    if kind == "port_scan":
        inside = alert.get("device_ip") == e.get("source")
        lines += [
            f"What NetWatch saw: {W(e['source'])} tried {e['ports_probed']} different services (ports) on "
            f"{W(e['target'])} {_seconds(e['duration_s'])}",
            f"Services that answered: {_ports(e.get('open_ports'))}",
            "Where it came from: " + ("a device inside your own Wi-Fi" if inside else "outside your network"),
        ]
        if e.get("crafted_packets"):
            lines.append("How: hand-made packets, typical of scanning tools such as nmap")
    elif kind == "host_sweep":
        lines += [f"What NetWatch saw: {W(e['source'])} contacted {e['hosts_probed']} different devices on your "
                  f"network within a minute"]
    elif kind == "syn_flood":
        n = e.get("distinct_sources", 1)
        src = W(e["sample_sources"][0]) if n == 1 and e.get("sample_sources") else f"{n} different addresses"
        dur = e["syn_count"] / max(float(e.get("syns_per_second") or 1), 0.001)
        lines += [
            f"What NetWatch saw: {src} started {e['syn_count']} connections to {W(e['target'])} on "
            f"{_ports(e.get('ports'))} {_seconds(dur)}, and never finished any of them",
        ]
    elif kind == "brute_force":
        lines += [
            f"What NetWatch saw: {W(e['source'])} logged in to {W(e['target'])} {e['connections']} times "
            f"within a minute, using {port_name(e['port'])}",
            "Each login was over " + _seconds(e.get("avg_duration_s", 0)).replace("in ", "", 1)
            + (", far faster than a person can type" if float(e.get("avg_duration_s") or 0) < 3 else ""),
        ]
    elif kind.endswith("_domain") or kind == "c2_ip":
        cat = e.get("category", "phishing")
        feeds = ", ".join(sorted({f["name"] for f in e.get("feeds", [])})) or "a threat list"
        lines += [
            f"What NetWatch saw: {W(alert.get('device_ip'))} "
            + ("connected to" if e.get("connected") else "looked up the address of") + f" {e['indicator']}",
            f"Why it is bad: {e['indicator']} is on {feeds} as a {cat} site",
            "Seen in: " + (", ".join(e.get("seen_via") or []) or "network traffic"),
        ]
        if e.get("confidence") == "low":
            lines.append("Note: the address belongs to a shared service, so only part of it may be malicious")
        kind = cat if cat in BACKGROUND else kind
    elif kind == "dga":
        lines += [
            f"What NetWatch saw: {W(e['source'])} looked up {e['nxdomain_names']} web addresses that do not exist "
            f"within a minute; {e['random_looking']} of them were random strings of letters and numbers",
            "Examples: " + ", ".join(e.get("sample_names", [])[:3]),
        ]
    elif kind == "dns_tunnel":
        lines += [
            f"What NetWatch saw: {W(e['source'])} sent {e['distinct_names']} very long, random-looking address "
            f"look-ups under {e['domain']} within a minute",
            f"About {e['approx_bytes_encoded']} bytes of hidden data could fit in those names",
        ]
    elif kind == "beaconing":
        dest = e.get("destination_name") or e["destination"]
        lines += [
            f"What NetWatch saw: {W(e['source'])} contacted {dest} ({e['destination']}) {e['check_ins']} times, "
            f"once every {_num(e['period_s'])} seconds like clockwork, sending little data each time",
            f"Service: {port_name(e['port'])}",
        ]
    elif kind == "new_fingerprint":
        lines += [
            f"What NetWatch saw: {W(e['source'])} made {e['connections']} encrypted connections in a way never seen "
            f"before on this device or any other device on your network",
        ] + ([f"Sites it connected to: {', '.join(e['sites'])}"] if e.get("sites") else [])
    elif kind in ("unusual_upload", "unusual_destinations"):
        what = {"upload_bytes": f"uploaded {e['this_minute'] / 1e6:.0f} MB in one minute",
                "destinations": f"talked to {e['this_minute']} different internet addresses in one minute",
                "ports": f"used {e['this_minute']} different services in one minute"}[e["metric"]]
        usual = {"upload_bytes": f"{e['usual_per_minute'] / 1e6:.1f} MB", "destinations": f"{e['usual_per_minute']:.0f} addresses",
                 "ports": f"{e['usual_per_minute']:.0f} services"}[e["metric"]]
        lines += [
            f"What NetWatch saw: {W(e['source'])} {what}",
            f"Its usual amount: about {usual} per minute, learned over {e['minutes_learned']} active minutes",
            f"That is {_num(float(e['times_above_usual']))} times its usual",
        ]
    elif kind.startswith("ml_"):
        shown = [W(t) for t in e.get("targets", [])[:3]]
        n = e["target_count"]
        named = ", ".join(shown[:-1]) + " and " + shown[-1] if len(shown) > 1 else "".join(shown)
        to = named if shown and n <= len(shown) else f"{n} addresses" + (f", including {named}" if shown else "")
        lines += [
            f"What NetWatch saw: {W(e['source'])} made {e['flows_flagged']} suspicious connections to {to}",
            f"Services involved: {_ports(e.get('ports'), 3)}",
        ]
        lines += _ml_lines(e, alone=True)
        if kind == "ml_scan" and e.get("target_count", 0) >= 2:
            lines.append(f"Why only the AI saw it: a few services on each of {e['target_count']} devices stays under "
                         "the fixed rules' limits, but the AI adds the probes up across devices")
        lines.append("Note: only the AI detector flagged this, no fixed rule did, so it could be a false alarm")
    else:
        lines.append(f"What NetWatch saw: {alert['title']}")

    if "ml" in e and not kind.startswith("ml_"):
        lines += _ml_lines(e["ml"], alone=False)
    if alert.get("count", 1) > 1:
        lines.append(f"It happened in {alert['count']} separate bursts")
    if kind in BACKGROUND:
        lines.append(f"Background: {BACKGROUND[kind]}")
    lines.append(f"Seriousness set by NetWatch: {alert['severity']}")
    return lines


def _short(ip: str | None, alert: dict, router_ip: str = "192.168.1.1") -> str:
    if not ip:
        return "A device"
    if ip == router_ip:
        return "your router"
    names = alert.get("devices") or {}
    info = names.get(ip) or (alert.get("device") if ip == alert.get("device_ip") else None)
    if info and info.get("hostname"):
        return f'"{info["hostname"]}"'
    if _kind_phrase(info):
        return f"a {_kind_phrase(info)}"
    return ip


def _cap(text: str) -> str:
    return text[0].upper() + text[1:] if text else text


def headline(alert: dict, router_ip: str = "192.168.1.1") -> str:
    """A one-line, jargon-free title for lists: who did what."""
    e, kind = alert.get("evidence") or {}, alert["kind"]
    S = lambda ip: _short(ip, alert, router_ip)  # noqa: E731
    try:
        if kind == "port_scan":
            return _cap(f"{S(e['source'])} is checking {S(e['target'])} for open doors (port scan)")
        if kind == "host_sweep":
            return _cap(f"{S(e['source'])} is mapping every device on your Wi-Fi")
        if kind == "syn_flood":
            n = e.get("distinct_sources", 1)
            src = S(e["sample_sources"][0]) if n == 1 and e.get("sample_sources") else f"{n} addresses"
            return _cap(f"{src} is flooding {S(e['target'])} with fake connections")
        if kind == "brute_force":
            return _cap(f"{S(e['source'])} is guessing passwords on {S(e['target'])}")
        if kind.endswith("_domain") or kind == "c2_ip":
            cat = e.get("category", "phishing")
            what = {"phishing": "a phishing site", "scam": "a scam site", "malware": "a malware site",
                    "c2": "a malware control server", "lab": "a test phishing site"}.get(cat, "a dangerous site")
            verb = "visited" if e.get("connected") else "looked up"
            return _cap(f"{S(alert.get('device_ip'))} {verb} {what}")
        if kind == "dga":
            return _cap(f"{S(e['source'])} is trying random web addresses, a sign of malware")
        if kind == "dns_tunnel":
            return _cap(f"{S(e['source'])} may be sneaking data out hidden in address look-ups")
        if kind == "beaconing":
            return _cap(f"{S(e['source'])} is checking in with an internet server like clockwork")
        if kind == "new_fingerprint":
            return _cap(f"New, unknown software is running on {S(e['source'])}")
        if kind == "unusual_upload":
            return _cap(f"{S(e['source'])} uploaded far more than it ever does")
        if kind == "unusual_destinations":
            what = "using far more services" if e.get("metric") == "ports" else "talking to far more places"
            return _cap(f"{S(e['source'])} is suddenly {what} than usual")
        if kind.startswith("ml_"):
            if kind == "ml_scan" and e.get("target_count", 0) >= 2:
                return f"AI detector: {S(e.get('source'))} is quietly scanning {e['target_count']} of your devices"
            fam = {"dos": "flooding traffic", "scan": "scanning", "brute_force": "password guessing",
                   "web_attack": "a web attack", "botnet": "botnet traffic"}.get(kind[3:], "an attack")
            return f"AI detector: {S(e.get('source'))} is sending what looks like {fam}"
    except (KeyError, IndexError, TypeError):
        pass
    return alert["title"]
