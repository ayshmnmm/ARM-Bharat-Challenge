"""Health of the Pi itself: the router's headroom matters as much as NetWatch's own numbers."""

from __future__ import annotations

import os
import time
from pathlib import Path

import psutil

from .config import Config


def _temp_c() -> float | None:
    try:
        return int(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000
    except (OSError, ValueError):
        return None


def _throttled() -> str | None:
    """Raspberry Pi firmware throttling flags, if readable without root."""
    p = Path("/sys/devices/platform/soc/soc:firmware/get_throttled")
    try:
        return p.read_text().strip()
    except OSError:
        return None


def snapshot(cfg: Config, eve_path: Path | None = None) -> dict:
    vm = psutil.virtual_memory()
    procs = []
    for p in psutil.process_iter(["pid", "name", "cmdline", "memory_info", "cpu_percent"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        # Only NetWatch's own processes (not shells that happen to have "netwatch" in a path)
        name = p.info.get("name") or ""
        if (name.startswith("python") and "-m netwatch" in cmd) or name in ("Suricata-Main", "suricata", "llama_main"):
            mi = p.info.get("memory_info")
            procs.append({"pid": p.info["pid"], "name": p.info["name"],
                          "rss_mb": round(mi.rss / 2**20, 1) if mi else None})
    router = {}
    for name in ("dnsmasq", "hostapd", "warp-svc"):
        router[name] = any(p.info.get("name") == name for p in psutil.process_iter(["name"]))
    eve_age = None
    if eve_path:
        try:  # the sensor's directory may belong to the service user (a dev API runs as the login user)
            eve_age = round(time.time() - eve_path.stat().st_mtime, 1)
        except OSError:
            pass
    return {
        "time": time.time(),
        "uptime_s": int(time.time() - psutil.boot_time()),
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "load": os.getloadavg(),
        "mem_total_mb": vm.total // 2**20, "mem_available_mb": vm.available // 2**20, "mem_percent": vm.percent,
        "temp_c": _temp_c(), "throttled": _throttled(),
        "netwatch_processes": procs,
        "netwatch_rss_mb": round(sum(p["rss_mb"] or 0 for p in procs), 1),
        "router_services": router,
        "db_size_mb": round(cfg.db_path.stat().st_size / 2**20, 2) if cfg.db_path.exists() else 0,
        "sensor_last_write_s": eve_age,
    }
