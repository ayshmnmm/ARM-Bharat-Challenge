"""Runtime configuration. Everything can be overridden with NETWATCH_* environment variables."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Addresses the API may bind to. eth0 (campus network) must never get a listener.
ALLOWED_BIND_HOSTS = {"127.0.0.1", "::1", "192.168.1.1"}


def _env(name: str, default: str) -> str:
    return os.environ.get(f"NETWATCH_{name}", default)


@dataclass(frozen=True)
class Config:
    home: Path = field(default_factory=lambda: Path(_env("HOME", str(REPO / "var"))))
    lan_cidr: str = field(default_factory=lambda: _env("LAN_CIDR", "192.168.1.0/24"))
    router_ip: str = field(default_factory=lambda: _env("ROUTER_IP", "192.168.1.1"))
    bind_host: str = field(default_factory=lambda: _env("BIND_HOST", "192.168.1.1"))
    bind_port: int = field(default_factory=lambda: int(_env("BIND_PORT", "8088")))
    suricata_config: Path = field(default_factory=lambda: Path(_env("SURICATA_CONFIG", str(REPO / "sensor" / "suricata.yaml"))))
    feeds_dir: Path = field(default_factory=lambda: Path(_env("FEEDS_DIR", str(REPO / "feeds" / "bundles" / "current"))))
    custom_feeds_dir: Path = field(default_factory=lambda: Path(_env("CUSTOM_FEEDS_DIR", str(REPO / "feeds" / "custom"))))
    web_dir: Path = field(default_factory=lambda: Path(_env("WEB_DIR", str(REPO / "web" / "out"))))
    explainer: str = field(default_factory=lambda: _env("EXPLAINER", "template"))  # template | llama
    llama_runner: str = field(default_factory=lambda: _env("LLAMA_RUNNER", ""))
    llama_model: str = field(default_factory=lambda: _env("LLAMA_MODEL", ""))
    llama_tokenizer: str = field(default_factory=lambda: _env("LLAMA_TOKENIZER", ""))
    llama_resident: bool = field(default_factory=lambda: _env("LLAMA_RESIDENT", "1") == "1")
    llama_threads: int = field(default_factory=lambda: int(_env("LLAMA_THREADS", "2")))
    retention_days: int = field(default_factory=lambda: int(_env("RETENTION_DAYS", "7")))
    ml_dir: Path = field(default_factory=lambda: Path(_env("ML_DIR", str(REPO / "models"))))
    ml_enabled: bool = field(default_factory=lambda: _env("ML", "1") == "1")
    pin: str = field(default_factory=lambda: _env("PIN", ""))  # empty = no login (dashboard open on the Wi-Fi)
    max_rss_mb: int = field(default_factory=lambda: int(_env("MAX_RSS_MB", "400")))

    @property
    def db_path(self) -> Path:
        return self.home / "netwatch.db"

    @property
    def lan(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.lan_cidr)

    def is_lan(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in self.lan
        except ValueError:
            return False

    def is_lan_host(self, ip: str | None) -> bool:
        """A real LAN device address: not the network or broadcast address."""
        return self.is_lan(ip) and ip not in (str(self.lan.network_address), str(self.lan.broadcast_address))


def load() -> Config:
    cfg = Config()
    cfg.home.mkdir(parents=True, exist_ok=True)
    return cfg
