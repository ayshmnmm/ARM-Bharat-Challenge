"""M0 machine-learning detector: a flow classifier trained on CIC-IDS2017, applied to Suricata flows."""

from __future__ import annotations

import json
from pathlib import Path


def load_card(model_dir: Path) -> dict | None:
    """The model card (metrics, features, classes). Cheap: no numpy or scikit-learn import."""
    try:
        return json.loads((Path(model_dir) / "flow_classifier.json").read_text())
    except (FileNotFoundError, ValueError):
        return None
