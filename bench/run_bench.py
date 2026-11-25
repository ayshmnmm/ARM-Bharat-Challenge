"""M6 benchmarks on the Pi: ML detector, offline pipeline, and Llama (one-shot vs resident, 1 vs 2 threads).

  .venv/bin/python bench/run_bench.py            # writes bench/results.json and bench/RESULTS.md

Everything runs at low priority. Llama uses at most 2 of the 4 cores: more would compete with routing,
so 3-4 threads are deliberately not measured on the live router.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

import psutil

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from netwatch import db  # noqa: E402
from netwatch.config import load  # noqa: E402

ART = REPO / "llm" / "artifacts"
MODEL = ART / "Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte"


def temp_c() -> float | None:
    try:
        return int(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000
    except OSError:
        return None


class Sampler:
    """Peak temperature, lowest free memory and peak child RSS while a step runs."""

    def __init__(self):
        self.max_temp, self.min_free_mb, self.peak_child_mb = 0.0, 1e9, 0.0
        self._stop = threading.Event()

    def __enter__(self):
        def loop():
            me = psutil.Process()
            while not self._stop.is_set():
                self.max_temp = max(self.max_temp, temp_c() or 0)
                self.min_free_mb = min(self.min_free_mb, psutil.virtual_memory().available / 2**20)
                rss = 0.0
                for ch in me.children(recursive=True):
                    try:
                        rss += ch.memory_info().rss / 2**20
                    except psutil.Error:
                        pass
                self.peak_child_mb = max(self.peak_child_mb, rss)
                self._stop.wait(0.5)
        self.t = threading.Thread(target=loop, daemon=True)
        self.t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.t.join()

    def result(self) -> dict:
        return {"max_temp_c": round(self.max_temp, 1), "min_free_mb": int(self.min_free_mb),
                "peak_model_rss_mb": int(self.peak_child_mb)}


def bench_ml(cfg) -> dict:
    import numpy as np
    rss0 = psutil.Process().memory_info().rss / 2**20
    t = time.perf_counter()
    from netwatch.ml.model import FlowModel
    m = FlowModel(cfg.ml_dir)
    load_s = time.perf_counter() - t
    rss1 = psutil.Process().memory_info().rss / 2**20
    rows = [{"dst_port": 443, "ts_start": 0.0, "ts_end": 1.0 + i % 7, "proto": "TCP", "pkts_out": 10 + i % 13,
             "pkts_in": 8 + i % 5, "bytes_out": 1200 + i, "bytes_in": 9000 + 3 * i} for i in range(20000)]
    t = time.perf_counter()
    m.score(rows)
    score_s = time.perf_counter() - t
    return {"model_load_s": round(load_s, 2), "rss_added_mb": int(rss1 - rss0),
            "flows_scored": len(rows), "flows_per_second": int(len(rows) / score_s),
            "us_per_flow": round(score_s / len(rows) * 1e6, 1), "threads": os.environ.get("OMP_NUM_THREADS", "default"),
            "numpy": np.__version__}


def bench_pipeline(cfg) -> list[dict]:
    from netwatch.pipeline import replay
    out = []
    for rel in ("captures/try.pcapng", "captures/nmap_scan.pcapng"):
        pcap = REPO / rel
        if not pcap.exists():
            continue
        with tempfile.TemporaryDirectory() as tmp:
            c = replace(cfg, home=Path(tmp), explainer="template")
            conn = db.connect(c.db_path)
            r = replay(conn, c, pcap, explain=False)
            dur = conn.execute("SELECT MAX(ts_end) - MIN(ts_start) FROM flows").fetchone()[0] or 0
        r.update(capture=pcap.name, capture_seconds=round(dur, 1),
                 realtime_factor=round(dur / r["total_s"], 1) if r["total_s"] else None)
        out.append(r)
    return out


def bench_llama(cfg) -> list[dict]:
    from netwatch.explain.facts import facts
    from netwatch.explain.llama import LlamaExplainer
    alert = {"id": 1, "kind": "brute_force", "severity": "high", "device_ip": "192.168.1.60", "title": "x", "count": 1,
             "evidence": {"source": "192.168.1.60", "target": "192.168.1.1", "port": 22, "service": "SSH",
                          "connections": 40, "avg_duration_s": 0.5}}
    lines = facts(alert)
    base = replace(cfg, explainer="llama", llama_runner=str(ART / "llama_main"), llama_model=str(MODEL),
                   llama_tokenizer=str(ART / "tokenizer.model"))
    runs = []

    def run(label: str, c, calls: int):
        LlamaExplainer._instance = None
        ex = LlamaExplainer.get(c)
        for i in range(calls):
            with Sampler() as s:
                t = time.perf_counter()
                try:
                    what, why, stats, ms = ex.write(lines)
                    ok = True
                except Exception as e:  # noqa: BLE001
                    stats, ok, what = {}, False, repr(e)
                wall = time.perf_counter() - t
            runs.append({"setup": label, "call": i + 1, "ok": ok, "wall_s": round(wall, 1),
                         "prefill_tps": stats.get("prefill_token_per_sec"), "decode_tps": stats.get("decode_token_per_sec"),
                         "prompt_tokens": stats.get("prompt_tokens"), "generated_tokens": stats.get("generated_tokens"),
                         **s.result()})
            print(json.dumps(runs[-1]), flush=True)
        if ex.resident:
            ex.resident.close()

    run("one-shot llama_main, 2 threads", replace(base, llama_resident=False, llama_threads=2), 1)
    if (ART / "netwatch_llm").exists():
        run("resident netwatch_llm, 2 threads", replace(base, llama_resident=True, llama_threads=2), 2)
        run("resident netwatch_llm, 1 thread", replace(base, llama_resident=True, llama_threads=1), 1)
    return runs


def main() -> None:
    os.nice(10)
    cfg = load()
    res = {"when": time.strftime("%Y-%m-%d %H:%M"), "machine": platform.machine(),
           "cpu": "Raspberry Pi 4, 4x Cortex-A72 @ 1.8 GHz", "kernel": platform.release(),
           "mem_total_mb": int(psutil.virtual_memory().total / 2**20), "start_temp_c": temp_c()}
    res["ml"] = bench_ml(cfg)
    print("ml", json.dumps(res["ml"]), flush=True)
    res["pipeline"] = bench_pipeline(cfg)
    print("pipeline", json.dumps(res["pipeline"]), flush=True)
    if MODEL.exists() and "--no-llama" not in sys.argv:
        res["llama"] = bench_llama(cfg)
    res["throttled"] = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True).stdout.strip()
    (REPO / "bench" / "results.json").write_text(json.dumps(res, indent=2) + "\n")
    md = [f"# NetWatch benchmarks ({res['when']}, {res['cpu']}, {res['mem_total_mb']} MB)", "",
          "## ML flow classifier", "", "| Model load | RAM added | Flows/s (1 thread) | µs per flow |", "|---|---|---|---|",
          f"| {res['ml']['model_load_s']} s | {res['ml']['rss_added_mb']} MB | {res['ml']['flows_per_second']:,} | "
          f"{res['ml']['us_per_flow']} |", "", "## Offline pipeline (pcap → Suricata → detectors, incl. ML)", "",
          "| Capture | Events | Capture length | Processing | × real time |", "|---|---|---|---|---|"]
    md += [f"| {p['capture']} | {p['events']:,} | {p['capture_seconds']} s | {p['total_s']} s | {p['realtime_factor']} |"
           for p in res["pipeline"]]
    if res.get("llama"):
        md += ["", "## Llama 3.2 1B (SpinQuant INT4) explanation of one alert", "",
               "| Setup | Call | OK | Wall time | Prefill tok/s | Decode tok/s | Tokens in → out | Peak model RSS | Min free RAM | Max temp |",
               "|---|---|---|---|---|---|---|---|---|---|"]
        md += [f"| {r['setup']} | {r['call']} | {'yes' if r['ok'] else 'no'} | {r['wall_s']} s | {r['prefill_tps']} | "
               f"{r['decode_tps']} | {r['prompt_tokens']} → {r['generated_tokens']} | {r['peak_model_rss_mb']} MB | "
               f"{r['min_free_mb']} MB | {r['max_temp_c']} °C |" for r in res["llama"]]
    md += ["", f"Firmware throttle flags after the run: `{res['throttled']}`", ""]
    (REPO / "bench" / "RESULTS.md").write_text("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
