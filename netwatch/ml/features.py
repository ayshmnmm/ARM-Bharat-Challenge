"""Flow features that mean the same thing in CIC-IDS2017 (CICFlowMeter) and in Suricata flow records.

Only features both tools can measure are used, so a model trained on the public dataset can score
live traffic. Fwd = the side that opened the connection (Suricata "toserver").

No timing features (duration, packets/s, bytes/s). An earlier model used them and learned the dataset's
wired-lab timing: it recognised scan probes only when the reply came within ~0.5 ms, which on a home
network is true only for the router itself. Probes answered over Wi-Fi (1-50 ms) scored 0 of 1,000.
Without timing the model flags the same real probes at any reply time (bench/ml_vs_rules.py).
"""

from __future__ import annotations

import numpy as np

FEATURES = [
    "dst_port", "fwd_pkts", "bwd_pkts", "fwd_payload", "bwd_payload", "fwd_mean", "bwd_mean", "bwd_fwd_ratio",
]

# Plain-English names, used when explaining what the model saw.
PLAIN = {
    "dst_port": "service port",
    "fwd_pkts": "packets sent",
    "bwd_pkts": "packets received in reply",
    "fwd_payload": "data sent",
    "bwd_payload": "data received",
    "fwd_mean": "data per packet sent",
    "bwd_mean": "data per reply packet",
    "bwd_fwd_ratio": "replies per packet sent",
}

PAD_BYTES = 10

# Per-packet header bytes Suricata counts but CICFlowMeter does not (Ethernet + IP + transport).
_HDR = {"TCP": 66, "UDP": 42}


def derive(dst_port, duration_s, fwd_pkts, bwd_pkts, fwd_payload, bwd_payload) -> np.ndarray:
    """Build the feature matrix from six base columns (array-likes of equal length). `duration_s` is
    accepted so both data sources share one signature, but is deliberately not used (see above)."""
    dst_port = np.asarray(dst_port, dtype=np.float32)
    fp = np.asarray(fwd_pkts, dtype=np.float64)
    bp = np.asarray(bwd_pkts, dtype=np.float64)
    fb = np.asarray(fwd_payload, dtype=np.float64)
    bb = np.asarray(bwd_payload, dtype=np.float64)
    # CICFlowMeter counts Ethernet padding as payload (a bare 54-byte SYN/RST is padded to 60, so every
    # scan probe "carries" 2-6 bytes); Suricata does not. Under 10 bytes per packet means "no data" on both.
    fb = np.where(fb < PAD_BYTES * np.maximum(fp, 1), 0.0, fb)
    bb = np.where(bb < PAD_BYTES * np.maximum(bp, 1), 0.0, bb)
    cols = [
        dst_port, fp, bp, fb, bb,
        fb / np.maximum(fp, 1), bb / np.maximum(bp, 1),
        bp / np.maximum(fp, 1),
    ]
    return np.column_stack(cols).astype(np.float32)


def from_flows(rows) -> np.ndarray:
    """Feature matrix for flow rows from the `flows` table (TCP/UDP only; caller filters)."""
    if not rows:
        return np.zeros((0, len(FEATURES)), dtype=np.float32)
    hdr = np.array([_HDR.get(r["proto"], 42) for r in rows], dtype=np.float64)
    fp = np.array([r["pkts_out"] or 0 for r in rows], dtype=np.float64)
    bp = np.array([r["pkts_in"] or 0 for r in rows], dtype=np.float64)
    fbytes = np.array([r["bytes_out"] or 0 for r in rows], dtype=np.float64)
    bbytes = np.array([r["bytes_in"] or 0 for r in rows], dtype=np.float64)
    return derive(
        [r["dst_port"] or 0 for r in rows],
        [max(r["ts_end"] - r["ts_start"], 0.0) for r in rows],
        fp, bp,
        np.maximum(fbytes - fp * hdr, 0), np.maximum(bbytes - bp * hdr, 0),
    )
