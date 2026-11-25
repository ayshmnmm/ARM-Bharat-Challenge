"""Llama 3.2 1B Instruct on ExecuTorch (XNNPACK, CPU) as the explanation provider.

Uses ExecuTorch's `llama_main` runner (built on the Pi by llm/build_runner.sh). Configure with:
  NETWATCH_EXPLAINER=llama
  NETWATCH_LLAMA_RUNNER=/path/to/llama_main
  NETWATCH_LLAMA_MODEL=/path/to/model.pte
  NETWATCH_LLAMA_TOKENIZER=/path/to/tokenizer.model
  NETWATCH_LLAMA_THREADS=2          # leave the other cores to the router

Division of labour: the rule engine and the ML detector decide the facts, risk level and next steps
(checkable, auditable). Llama is given those facts as plain "label: value" lines (explain/facts.py:
device names, services, counts, the ML verdict, background) and writes its own two-part explanation
for a non-technical reader. Output without both parts, or with an address or number that is not in
the facts, or that plays the alert down, raises, and the caller falls back to the rule-based text.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import re
import subprocess
import tempfile
import time
from pathlib import Path

import psutil

from ..config import Config
from . import Explanation

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "Explain a home Wi-Fi security alert to someone non-technical, using only the facts. Answer in two parts:\n"
    "What happened: two short sentences, who did what, in everyday words.\n"
    "Why it matters: one or two short sentences on the danger.\n"
    "Copy addresses and numbers exactly; add none. No jargon. Never call it normal or safe."
)
# One short worked example: a 1B model copies a demonstrated style far more reliably than it follows
# rules. Kept small because reading the prompt (prefill) is most of the time on the Pi.
EXAMPLE_FACTS = [
    "What NetWatch saw: a laptop on your Wi-Fi (192.168.1.20) logged in to a camera (192.168.1.5) 25 times "
    "within a minute, using port 21, file transfer (FTP)",
    "Background: Many quick logins in a row usually mean a program is guessing passwords.",
]
EXAMPLE_ANSWER = (
    "What happened: A laptop (192.168.1.20) tried to log in to your camera 25 times in one minute, "
    "far faster than a person could.\n"
    "Why it matters: A program is probably guessing the camera's password. If it gets in, someone could "
    "watch the camera or use it to reach your other devices."
)

TIMEOUT_S = 240
LOAD_TIMEOUT_S = 90
IDLE_EXIT_S = 300          # resident runner gives its ~1.4 GB back after 5 idle minutes
MIN_FREE_MB = 1700         # never start the model unless the router keeps this much headroom
MAX_NEW_TOKENS = 140
_STATS = re.compile(r"PyTorchObserver\s+(\{.*\})")
_SPECIAL = re.compile(r"<\|[^|>]*\|>")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# Worked examples per task: the 1B model follows the format of the example it is shown.
EXAMPLES = {
    "alert": (None, None),  # filled below from EXAMPLE_FACTS / EXAMPLE_ANSWER
    "summary": ([
        "Period: this week",
        "New devices joined the Wi-Fi this week",
        "Kinds of alerts this week: phishing sites, port scans",
        "Some alerts were rated urgent",
        "Some alerts have not been looked at yet",
    ], "What happened: This week new devices joined your Wi-Fi, and NetWatch saw port scans and a visit to a "
       "phishing site.\n"
       "Why it matters: A serious alert is still waiting for you, so open it first to see what to do. Then check "
       "that you recognise the new devices on your Wi-Fi."),
}


def format_facts(lines: list[str]) -> str:
    return "\n".join(f"- {ln}" for ln in lines)


def build_prompt(facts: str, task: str = "alert") -> str:
    turn = "<|start_header_id|>{}<|end_header_id|>\n\n{}<|eot_id|>"
    ex_facts, ex_answer = EXAMPLES.get(task, (None, None))
    if ex_facts is None:
        ex_facts, ex_answer = EXAMPLE_FACTS, EXAMPLE_ANSWER
    system = SYSTEM_PROMPT.replace("a home Wi-Fi security alert", {
        "summary": "a week of home Wi-Fi security"}.get(task, "a home Wi-Fi security alert"))
    return (
        "<|begin_of_text|>" + turn.format("system", system)
        + turn.format("user", f"Facts:\n{format_facts(ex_facts)}") + turn.format("assistant", ex_answer)
        + turn.format("user", f"Facts:\n{facts}") + "<|start_header_id|>assistant<|end_header_id|>\n\n"
    )


def generated_text(stdout: str, facts: str) -> str:
    """The runner echoes the prompt before generating. Keep only what comes after it, so the alert
    text inside the prompt can never be mistaken for the model's answer."""
    i = stdout.rfind(facts)
    if i >= 0:
        stdout = stdout[i + len(facts):]
    j = stdout.rfind("assistant<|end_header_id|>")
    if j >= 0:
        stdout = stdout[j + len("assistant<|end_header_id|>"):]
    stdout = stdout.split("<|eot_id|>")[0]
    stdout = "\n".join(ln for ln in stdout.splitlines() if not ln.startswith("PyTorchObserver"))
    return _SPECIAL.sub("", stdout).strip()


_PREAMBLE = re.compile(r"^(here is|here's|sure|okay)[^:]{0,60}:\s*", re.I)
_NUMBER = re.compile(r"(?<![\d.])\d+(?:\.\d+)?(?![\d.])")
_REASSURING = ("normal", "safe", "harmless", "worry", "not a concern")
# A repeated or extra label ends that part: the 1B model sometimes restates "Why it matters:" or adds
# "Why it's bad:" with a paraphrase of what it already said.
# Claims about outcomes the facts never state (the model invented "6 false positives" in a summary).
_UNSUPPORTED = ("false positive", "false alarm", "resolved", "fixed", "no longer", "blocked by netwatch", "stopped")
# For test alerts ("not a real threat") the answer must not invent danger.
_ALARMING = ("hack", "vulnerab", "attack", "compromis", "infect", "steal", "danger")
# Kinds of device the model may only name if the facts do (seen live: it called a Google server "your
# camera", borrowing the word from its worked example).
_DEVICE = re.compile(r"\b(camera|phone|smartphone|tablet|tv|television|printer|smart plug|speaker|doorbell|"
                     r"console|fridge|thermostat)s?\b", re.I)
_LABEL = re.compile(r"\b(?:what happened|why it matters|why it'?s bad|why it is bad|what to do)\s*:", re.I)
_PARTS = re.compile(r"what happened\s*:\s*(?P<what>.+?)\s*why it matters\s*:\s*(?P<why>.+)", re.I | re.S)


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rfind(". ")
    return text[: cut + 1] if cut > limit // 4 else text[:limit]


def parse_output(text: str, facts: str) -> tuple[str, str]:
    """(what happened, why it matters) if the answer is grounded in the facts; else raise."""
    text = _PREAMBLE.sub("", text.strip()).strip().strip('"')
    m = _PARTS.search(text.replace("**", ""))
    if m:
        what, why = (_LABEL.split(" ".join(m.group(k).split()))[0].strip().strip('"') for k in ("what", "why"))
    else:
        # No labels: accept plain prose (never a list) and split it: first two sentences, then the rest.
        if re.search(r"^\s*([-*•]|\d+\.)\s", text, re.M):
            raise ValueError("model output is a list, not the two parts")
        sentences = re.split(r"(?<=[.!?])\s+", " ".join(text.split()))
        if len(sentences) < 2:
            raise ValueError("model output is missing the two parts")
        cut = 2 if len(sentences) > 2 else 1
        what, why = " ".join(sentences[:cut]), " ".join(sentences[cut:])
    both = f"{what} {why}"
    if len(what) < 30 or len(why) < 20:
        raise ValueError("model output too short")
    if "{" in both:
        raise ValueError("model output is not plain text")
    invented = set(_IPV4.findall(both)) - set(_IPV4.findall(facts))
    if invented:
        raise ValueError(f"model mentioned addresses not in the facts: {sorted(invented)}")
    numbers = set(_NUMBER.findall(_IPV4.sub(" ", both))) - set(_NUMBER.findall(_IPV4.sub(" ", facts)))
    if numbers:
        raise ValueError(f"model mentioned numbers not in the facts: {sorted(numbers)}")
    low, flow = both.lower(), facts.lower()
    if any(w in low and w not in flow for w in _REASSURING):
        raise ValueError("model played the alert down")
    if any(w in low and w not in flow for w in _UNSUPPORTED):
        raise ValueError("model claimed an outcome that is not in the facts")
    if "not a real threat" in flow and any(w in low for w in _ALARMING):
        raise ValueError("model made a test alert sound dangerous")
    devices = {m.lower() for m in _DEVICE.findall(both)} - {m.lower() for m in _DEVICE.findall(facts)}
    if devices:
        raise ValueError(f"model named a kind of device that is not in the facts: {sorted(devices)}")
    return _clip(what, 400), _clip(why, 350)


def parse_stats(output: str) -> dict:
    m = _STATS.search(output)
    if not m:
        return {}
    try:
        s = json.loads(m.group(1))
    except json.JSONDecodeError:
        return {}
    return {k: s[k] for k in ("prefill_token_per_sec", "decode_token_per_sec", "prompt_tokens", "generated_tokens",
                              "model_load_start_ms", "model_load_end_ms", "inference_start_ms", "first_token_ms",
                              "inference_end_ms") if k in s}


class LlamaExplainer:
    _instance: "LlamaExplainer | None" = None

    def __init__(self, cfg: Config):
        for name, value in (("LLAMA_RUNNER", cfg.llama_runner), ("LLAMA_MODEL", cfg.llama_model),
                            ("LLAMA_TOKENIZER", cfg.llama_tokenizer)):
            if not value or not Path(value).exists():
                raise FileNotFoundError(f"NETWATCH_{name} not set or missing: {value!r}")
        self.cfg = cfg
        server = Path(cfg.llama_runner).with_name("netwatch_llm")
        self.resident = ResidentRunner(cfg, server) if server.exists() and cfg.llama_resident else None

    @classmethod
    def get(cls, cfg: Config) -> "LlamaExplainer":
        if cls._instance is None or cls._instance.cfg != cfg:
            cls._instance = cls(cfg)
        return cls._instance

    def _run(self, prompt: str) -> str:
        """Run the model on a full prompt; returns everything the runner printed. Uses the resident
        runner (model stays loaded between prompts) when it is installed, else one llama_main per prompt."""
        if self.resident is not None:
            try:
                return self.resident.ask(prompt)
            except Exception as e:  # noqa: BLE001
                log.warning("resident runner failed (%s); falling back to llama_main", e)
                self.resident.close()
        return self._run_once(prompt)

    def _run_once(self, prompt: str) -> str:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=True) as pf:
            pf.write(prompt)
            pf.flush()
            proc = subprocess.run(
                ["nice", "-n", "10", self.cfg.llama_runner,
                 f"--model_path={self.cfg.llama_model}", f"--tokenizer_path={self.cfg.llama_tokenizer}",
                 f"--prompt_file={pf.name}", "--temperature=0", f"--max_new_tokens={MAX_NEW_TOKENS}",
                 f"--cpu_threads={self.cfg.llama_threads}"],
                capture_output=True, text=True, timeout=TIMEOUT_S,
            )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr[-500:])
        return proc.stdout + "\n" + proc.stderr

    def write(self, lines: list[str], task: str = "alert") -> tuple[str, str, dict, int]:
        """(what happened, why it matters, runner stats, latency ms) from grounded fact lines.

        One model at a time across all NetWatch processes (live detection and the API both use it):
        two copies would need ~2.8 GB of the router's 4 GB."""
        facts = format_facts(lines)
        free_mb = psutil.virtual_memory().available / 2**20
        if free_mb < MIN_FREE_MB and not (self.resident and self.resident.alive()):
            raise MemoryError(f"only {free_mb:.0f} MB free; the router comes first")
        with _model_lock(self.cfg):
            t = time.monotonic()
            out = self._run(build_prompt(facts, task))
            elapsed = int((time.monotonic() - t) * 1000)
        raw = generated_text(out, facts)
        try:
            what, why = parse_output(raw, facts)
        except ValueError as e:
            log.warning("Llama answer rejected (%s): %r", e, raw[:400])
            raise
        return what, why, parse_stats(out), elapsed

    def explain(self, alert: dict) -> Explanation:
        from .facts import facts as alert_facts
        from .templates import explain as template_explain

        lines = alert_facts(alert, self.cfg.router_ip)
        what, why, stats, elapsed = self.write(lines)
        base = template_explain(alert)  # risk level and next steps stay with the rules
        return Explanation(summary=what, why=why, risk=base.risk, actions=base.actions, facts=lines,
                           provider="llama-executorch", model=Path(self.cfg.llama_model).name, latency_ms=elapsed,
                           stats=stats)


class ResidentRunner:
    """netwatch_llm (llm/server/netwatch_llm.cpp): keeps the model loaded between prompts and exits by
    itself after IDLE_EXIT_S without work, giving the router its memory back."""

    END = "<<<NETWATCH_END>>>"
    READY = "<<<NETWATCH_READY>>>"

    def __init__(self, cfg: Config, binary: Path):
        self.cfg, self.binary = cfg, binary
        self.proc: subprocess.Popen | None = None
        self.lines: "queue.Queue[str | None]" = queue.Queue()
        self.loads = 0

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _start(self) -> None:
        self.close()
        self.proc = subprocess.Popen(
            ["nice", "-n", "10", str(self.binary), f"--model_path={self.cfg.llama_model}",
             f"--tokenizer_path={self.cfg.llama_tokenizer}", f"--cpu_threads={self.cfg.llama_threads}",
             f"--max_new_tokens={MAX_NEW_TOKENS}", f"--idle_exit_s={IDLE_EXIT_S}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.lines = queue.Queue()
        q, out = self.lines, self.proc.stdout

        def pump() -> None:
            for line in out:
                q.put(line)
            q.put(None)

        threading.Thread(target=pump, daemon=True, name="netwatch-llm").start()
        self._read_until(self.READY, LOAD_TIMEOUT_S)
        self.loads += 1

    def _read_until(self, marker: str, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        buf = []
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no {marker} within {timeout:.0f} s")
            line = self.lines.get(timeout=left)
            if line is None:
                raise RuntimeError("netwatch_llm exited")
            if line.strip() == marker:
                return "".join(buf)
            buf.append(line)

    def ask(self, prompt: str) -> str:
        if not self.alive():
            self._start()
        assert self.proc and self.proc.stdin
        data = prompt.encode()
        self.proc.stdin.write(f"{len(data)}\n")
        self.proc.stdin.write(prompt)
        self.proc.stdin.flush()
        out = self._read_until(self.END, TIMEOUT_S)
        if "NETWATCH_ERROR" in out:
            raise RuntimeError("generation failed")
        return out

    def close(self) -> None:
        if self.alive():
            self.proc.kill()
            self.proc.wait(5)
        self.proc = None


class _model_lock:
    """Inter-process lock (flock) on a file in the NetWatch home directory."""

    def __init__(self, cfg: Config):
        self.path = cfg.home / "llama.lock"

    def __enter__(self):
        import fcntl
        self.fh = open(self.path, "a")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        import fcntl
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()
