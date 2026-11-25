"""Load the trained flow classifier and score flow records."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path

import numpy as np

from .features import FEATURES, from_flows

log = logging.getLogger(__name__)
_lock = threading.Lock()
_cache: dict[str, "FlowModel | None"] = {}


class FlowModel:
    def __init__(self, model_dir: Path):
        card_path = model_dir / "flow_classifier.json"
        model_path = model_dir / "flow_classifier.joblib"
        self.card = json.loads(card_path.read_text())
        digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
        if digest != self.card["sha256"]:
            # joblib files are pickles: never load one that is not the file we trained.
            raise ValueError(f"{model_path} does not match the checksum in {card_path.name}")
        if self.card["features"] != FEATURES:
            raise ValueError("model was trained on a different feature set")
        os.environ.setdefault("OMP_NUM_THREADS", "1")
        import joblib
        self.clf = joblib.load(model_path)
        self.classes: list[str] = self.card["classes"]

    def score(self, rows) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """(feature matrix, predicted class index, probability of that class) per flow row."""
        X = from_flows(rows)
        if not len(X):
            return X, np.zeros(0, int), np.zeros(0)
        proba = self.clf.predict_proba(X)
        idx = proba.argmax(axis=1)
        return X, idx, proba[np.arange(len(idx)), idx]


def get_model(model_dir: Path) -> FlowModel | None:
    """Cached model, or None if it is not installed (the ML detector is then skipped)."""
    key = str(model_dir)
    with _lock:
        if key not in _cache:
            try:
                _cache[key] = FlowModel(model_dir)
                log.info("ML flow classifier loaded from %s", model_dir)
            except FileNotFoundError:
                log.warning("ML flow classifier not found in %s; ML detector disabled", model_dir)
                _cache[key] = None
        return _cache[key]
