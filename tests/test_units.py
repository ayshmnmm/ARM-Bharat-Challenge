"""Guards on the service definitions: the router-safety fences must never be edited away."""

from __future__ import annotations

import configparser

import pytest

from .conftest import REPO

UNITS = REPO / "setup" / "systemd"


def _unit(name: str) -> dict[str, str]:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    cp.read(UNITS / f"{name}.service")
    return dict(cp["Service"])


@pytest.mark.parametrize("name", ["netwatch-sensor", "netwatch-live", "netwatch-web"])
def test_common_hardening(name):
    s = _unit(name)
    assert s["User"] == "netwatch"
    assert s["OOMScoreAdjust"] == "500" and s["Nice"] == "10"
    assert s["NoNewPrivileges"] == "yes" and s["ProtectSystem"] == "strict"
    assert "LimitAS" in s and "CPUQuota" in s
    directives = [ln for ln in (UNITS / f"{name}.service").read_text().splitlines() if not ln.startswith("#")]
    assert not any("eth0" in ln for ln in directives)


def test_sensor_is_wlan0_only_and_passive():
    s = _unit("netwatch-sensor")
    assert "--af-packet=wlan0" in s["ExecStart"]
    assert set(s["CapabilityBoundingSet"].split()) == {"CAP_NET_RAW", "CAP_NET_ADMIN"}
    cfg = (REPO / "sensor" / "suricata.yaml").read_text()
    assert "interface: wlan0" in cfg and "disable-promisc: yes" in cfg and "copy-mode: none" in cfg
    assert "interface: eth0" not in cfg


def test_live_has_no_network():
    s = _unit("netwatch-live")
    assert s["IPAddressDeny"] == "any" and "IPAddressAllow" not in s
    assert s["RestrictAddressFamilies"] == "AF_UNIX"


def test_web_is_fenced_to_the_lan():
    s = _unit("netwatch-web")
    assert "--host 192.168.1.1" in s["ExecStart"]
    assert s["IPAddressDeny"] == "any"
    assert set(s["IPAddressAllow"].split()) == {"192.168.1.0/24", "127.0.0.0/8", "::1/128"}
