from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
needs_suricata = pytest.mark.skipif(not shutil.which("suricata"), reason="suricata not installed")


@pytest.fixture(scope="session")
def lab_pcaps(tmp_path_factory) -> Path:
    """Synthetic attack captures, generated fresh (never committed, never sent on a network)."""
    out = tmp_path_factory.mktemp("lab")
    spec = importlib.util.spec_from_file_location("make_pcaps", REPO / "lab" / "make_pcaps.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["make_pcaps"] = mod
    spec.loader.exec_module(mod)
    mod.main(out)
    return out


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("NETWATCH_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("NETWATCH_FEEDS_DIR", str(tmp_path / "no-bundle"))
    monkeypatch.setenv("NETWATCH_WEB_DIR", str(tmp_path / "no-web"))
    from netwatch.config import load
    return load()
