"""Train the flow classifier on CIC-IDS2017 (MachineLearningCVE CSVs).

  python -m netwatch ml-train --data var/datasets/cic/MachineLearningCVE

Runs on the Pi at low priority (2 threads). Writes models/flow_classifier.joblib plus a JSON card
with the features, classes, test metrics and the benign reference values used in explanations.
"""

from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter
from pathlib import Path

import numpy as np

from .features import FEATURES, derive

# CIC-IDS2017 labels -> the attack families NetWatch reports. Infiltration/Heartbleed have too few
# flows (36 and 11) to learn from and are left out.
LABELS = {
    "BENIGN": "benign",
    "DoS Hulk": "dos", "DoS GoldenEye": "dos", "DoS slowloris": "dos", "DoS Slowhttptest": "dos", "DDoS": "dos",
    "PortScan": "scan",
    "FTP-Patator": "brute_force", "SSH-Patator": "brute_force",
    "Bot": "botnet",
}


def family(label: str) -> str | None:
    """Map a CIC-IDS2017 label to a NetWatch family, or None to leave the flow out.

    Web attacks (brute force, XSS, SQL injection; 2,180 flows) are left out: at flow level they look
    like ordinary web browsing (tested as their own class: precision 0.17, recall 0.08 at the
    operating point). Catching them needs payload inspection, not flow statistics."""
    if label.startswith("Web Attack"):
        return None
    return LABELS.get(label)


CLASSES = ["benign", "dos", "scan", "brute_force", "botnet"]
BASE = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets"]
MAX_BENIGN = 600_000
OPERATING_PROB = 0.9  # must match detectors/ml.py ML_MIN_PROB
SEED = 7


def load(data_dir: Path) -> tuple[np.ndarray, np.ndarray, dict]:
    # Columns are streamed into compact arrays (~150 MB for 2.8 M rows) rather than Python lists of rows
    # (~700 MB), so training fits beside a loaded Llama on the live router.
    import array
    base = [array.array("d") for _ in BASE]
    labels, raw_counts = array.array("b"), Counter()
    for path in sorted(data_dir.glob("*.csv")):
        with open(path, newline="", encoding="latin-1") as fh:
            reader = csv.reader(fh)
            header = [h.strip() for h in next(reader)]
            idx = [header.index(c) for c in BASE]
            li = header.index("Label")
            for row in reader:
                if len(row) <= li:
                    continue
                lab = row[li].strip()
                raw_counts[lab] += 1
                cls = family(lab)
                if cls is None:
                    continue
                try:
                    vals = [float(row[i]) for i in idx]
                except ValueError:
                    continue
                for col, v in zip(base, vals):
                    col.append(v)
                labels.append(CLASSES.index(cls))
    b = np.column_stack([np.frombuffer(col, dtype=np.float64) for col in base])
    y = np.frombuffer(labels, dtype=np.int8).copy()
    # Flow Duration is microseconds; negative durations are known CICFlowMeter glitches.
    keep = b[:, 1] >= 0
    return b[keep], y[keep], dict(raw_counts)


def features_of(b: np.ndarray) -> np.ndarray:
    return derive(b[:, 0], b[:, 1] / 1e6, b[:, 2], b[:, 3], b[:, 4], b[:, 5])


def dedupe_and_cap(b: np.ndarray, y: np.ndarray, rng) -> tuple[np.ndarray, np.ndarray]:
    """Drop exact duplicate *records* (all six raw columns and the label), which otherwise leak between
    train and test, then cap the benign class so attacks are not drowned out.

    Duplicates are judged on the raw record, not on the model's features: without timing features,
    thousands of different scan probes look alike to the model (that is what a scan is), and de-duplicating
    in feature space shrank the scan class to 1,238 rows and taught the model to ignore scans."""
    _, first = np.unique(np.column_stack([b, y.astype(np.float64)]), axis=0, return_index=True)
    b, y = b[first], y[first]
    benign = np.flatnonzero(y == 0)
    if len(benign) > MAX_BENIGN:
        drop = rng.choice(benign, len(benign) - MAX_BENIGN, replace=False)
        mask = np.ones(len(y), bool)
        mask[drop] = False
        b, y = b[mask], y[mask]
    return b, y


def train(data_dir: Path, out_dir: Path, threads: int = 2) -> dict:
    import os
    os.environ.setdefault("OMP_NUM_THREADS", str(threads))
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.inspection import permutation_importance
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split
    import joblib

    rng = np.random.default_rng(SEED)
    t = time.time()
    b, y, raw = load(data_dir)
    n_loaded = len(y)
    b, y = dedupe_and_cap(b, y, rng)
    X = features_of(b)
    del b
    print(f"loaded {n_loaded} flows, {len(y)} after dedupe/cap in {time.time() - t:.0f}s: "
          f"{ {CLASSES[k]: int(v) for k, v in zip(*np.unique(y, return_counts=True))} }")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)

    # Balanced weights so rare families (web attacks, botnet) count; benign keeps weight 1.
    counts = np.bincount(ytr, minlength=len(CLASSES))
    # No class re-weighting: weighted runs lifted rare-class recall but mislabelled ~1% of benign
    # flows as web attack/botnet (precision 0.30/0.56), which on a home network means false alarms.
    w = np.ones(len(ytr))
    clf = HistGradientBoostingClassifier(
        max_iter=250, learning_rate=0.1, max_leaf_nodes=48, min_samples_leaf=40,
        l2_regularization=1.0, categorical_features=None, random_state=SEED,
        early_stopping=True, validation_fraction=0.1, n_iter_no_change=15,
    )
    t = time.time()
    clf.fit(Xtr, ytr, sample_weight=w)
    fit_s = time.time() - t
    t = time.time()
    pred = clf.predict(Xte)
    infer_us = (time.time() - t) / len(Xte) * 1e6
    report = classification_report(yte, pred, labels=range(len(CLASSES)), target_names=CLASSES,
                                   output_dict=True, zero_division=0)
    print(classification_report(yte, pred, labels=range(len(CLASSES)), target_names=CLASSES, digits=4,
                                zero_division=0))
    cm = confusion_matrix(yte, pred, labels=range(len(CLASSES)))
    # The operating point used live: a flow only counts as an attack at >= 0.9 confidence.
    proba = clf.predict_proba(Xte)
    pred_op = np.where(proba.max(axis=1) >= OPERATING_PROB, proba.argmax(axis=1), 0)
    report_op = classification_report(yte, pred_op, labels=range(len(CLASSES)), target_names=CLASSES,
                                      output_dict=True, zero_division=0)
    print("at operating point (attack only if confidence >= 0.9):")
    print(classification_report(yte, pred_op, labels=range(len(CLASSES)), target_names=CLASSES, digits=4,
                                zero_division=0))
    benign_fp_rate = float(np.mean(pred_op[yte == 0] != 0))

    sub = rng.choice(len(yte), min(20_000, len(yte)), replace=False)
    imp = permutation_importance(clf, Xte[sub], yte[sub], n_repeats=3, random_state=SEED, scoring="f1_macro")
    importance = sorted(((FEATURES[i], round(float(m), 4)) for i, m in enumerate(imp.importances_mean)),
                        key=lambda kv: -kv[1])

    benign = X[y == 0]
    benign_median = {f: float(np.median(benign[:, i])) for i, f in enumerate(FEATURES)}

    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "flow_classifier.joblib"
    joblib.dump(clf, model_path, compress=3)
    import sklearn
    card = {
        "name": "NetWatch flow classifier",
        "algorithm": "HistGradientBoostingClassifier (gradient-boosted decision trees)",
        "sklearn_version": sklearn.__version__,
        "dataset": "CIC-IDS2017 MachineLearningCVE (Sharafaldin et al., ICISSP 2018)",
        "features": FEATURES,
        "classes": CLASSES,
        "label_map": LABELS,
        "left_out": {"Web Attack * (Brute Force, XSS, Sql Injection)": "not separable from browsing by flow statistics",
                     "Infiltration": "36 flows", "Heartbleed": "11 flows"},
        "raw_label_counts": raw,
        "rows_loaded": n_loaded,
        "rows_after_dedupe": int(len(y)),
        "train_rows": int(len(ytr)), "test_rows": int(len(yte)),
        "iterations": int(clf.n_iter_),
        "fit_seconds": round(fit_s, 1),
        "inference_us_per_flow": round(infer_us, 2),
        "test": {
            "accuracy": round(report["accuracy"], 4),
            "macro_f1": round(report["macro avg"]["f1-score"], 4),
            "per_class": {c: {k: round(report[c][k], 4) for k in ("precision", "recall", "f1-score", "support")}
                          for c in CLASSES},
            "confusion_matrix": cm.tolist(),
        },
        "operating_point": {
            "min_confidence": OPERATING_PROB,
            "accuracy": round(report_op["accuracy"], 4),
            "macro_f1": round(report_op["macro avg"]["f1-score"], 4),
            "benign_flows_misflagged": round(benign_fp_rate, 5),
            "per_class": {c: {k: round(report_op[c][k], 4) for k in ("precision", "recall", "f1-score")}
                          for c in CLASSES},
        },
        "permutation_importance": importance,
        "benign_median": benign_median,
        "sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    (out_dir / "flow_classifier.json").write_text(json.dumps(card, indent=2) + "\n")
    print(f"saved {model_path} ({model_path.stat().st_size // 1024} KB), fit {fit_s:.0f}s, "
          f"{infer_us:.1f} us/flow, macro F1 {card['test']['macro_f1']}")
    return card
