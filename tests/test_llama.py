"""Llama provider against a fake llama_main that behaves like ExecuTorch's runner:
it echoes the prompt (alert text included), streams the answer, then prints timing stats."""

from __future__ import annotations

import json
import stat
import threading

import pytest

from netwatch import db
from netwatch.alerts import AlertDraft, upsert
from netwatch.config import load
from netwatch.explain import explain_alert, explain_pending
from netwatch.explain.facts import facts as alert_facts
from netwatch.explain.llama import format_facts, generated_text, parse_output
from netwatch.explain.templates import explain as template_explain

WHAT = ("A laptop on your Wi-Fi (192.168.1.60) tried to log in to your router 40 times in about a minute. "
        "Each try was over almost instantly.")
WHY = "A program is probably guessing the router's password. If it gets in, it could take over your internet."
ANSWER = f"What happened: {WHAT}\nWhy it matters: {WHY}"
STATS = {"prefill_token_per_sec": 8.4, "decode_token_per_sec": 4.0, "prompt_tokens": 180,
         "generated_tokens": 45, "inference_start_ms": 1000, "first_token_ms": 22000, "inference_end_ms": 33000}


def _fake_runner(tmp_path, answer: str, exit_code: int = 0):
    script = tmp_path / "llama_main"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "args = dict(a[2:].split('=', 1) for a in sys.argv[1:] if '=' in a)\n"
        "assert args['temperature'] == '0' and args['cpu_threads'] == '2', args\n"
        "print(open(args['prompt_file']).read(), end='')\n"     # echo, like the real runner
        f"print({answer!r} + '<|eot_id|>')\n"
        f"print('PyTorchObserver ' + {json.dumps(STATS)!r})\n"   # the real runner prints stats on stdout
        f"sys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    model, tok = tmp_path / "m.pte", tmp_path / "tokenizer.model"
    model.write_bytes(b"x")
    tok.write_bytes(b"x")
    return script, model, tok


@pytest.fixture
def llama_cfg(cfg, tmp_path, monkeypatch):
    def make(answer=ANSWER, exit_code=0):
        script, model, tok = _fake_runner(tmp_path, answer, exit_code)
        monkeypatch.setenv("NETWATCH_EXPLAINER", "llama")
        monkeypatch.setenv("NETWATCH_LLAMA_RUNNER", str(script))
        monkeypatch.setenv("NETWATCH_LLAMA_MODEL", str(model))
        monkeypatch.setenv("NETWATCH_LLAMA_TOKENIZER", str(tok))
        monkeypatch.setattr("netwatch.explain.llama.MIN_FREE_MB", 0)  # tests must not depend on the Pi's free RAM
        return load()
    return make


ALERT = {"id": 1, "kind": "brute_force", "severity": "high", "device_ip": "192.168.1.60",
         "title": "Possible SSH password guessing",
         "evidence": {"source": "192.168.1.60", "target": "192.168.1.1", "port": 22, "service": "SSH", "connections": 40,
                      "avg_duration_s": 0.5, "avg_bytes_sent": 900}}
FACTS = format_facts(alert_facts(ALERT))


def test_llama_writes_both_parts_rules_keep_risk_and_actions(llama_cfg):
    exp = explain_alert(ALERT, llama_cfg())
    base = template_explain(ALERT)
    assert exp.provider == "llama-executorch" and exp.model == "m.pte"
    assert (exp.summary, exp.why) == (WHAT, WHY)
    assert (exp.risk, exp.actions) == (base.risk, base.actions)
    assert exp.facts == alert_facts(ALERT)
    assert exp.stats["decode_token_per_sec"] == 4.0 and exp.stats["prompt_tokens"] == 180


def test_model_gets_plain_facts_not_raw_json():
    assert "{" not in FACTS and "192.168.1.60" in FACTS and "40 times" in FACTS
    assert "remote login (SSH)" in FACTS and "your router (192.168.1.1)" in FACTS  # jargon translated


def test_device_names_reach_the_facts():
    named = {**ALERT, "devices": {"192.168.1.60": {"hostname": "kids-laptop", "kind": "Laptop", "vendor": "Intel"}}}
    assert 'the device "kids-laptop" (192.168.1.60, made by Intel)' in format_facts(alert_facts(named))


def test_echoed_prompt_is_never_taken_as_the_answer():
    out = (f"<|begin_of_text|>system...<|eot_id|>user<|end_header_id|>\n\nFacts:\n{FACTS}<|eot_id|>"
           f"<|start_header_id|>assistant<|end_header_id|>\n\n{ANSWER}<|eot_id|>\nPyTorchObserver {{}}")
    assert generated_text(out, FACTS) == ANSWER


@pytest.mark.parametrize("answer, code", [
    ("OK.", 0),                                                     # too short
    ("Here's what happened:\n\n* 40 logins\n* from 192.168.1.60 to your router", 0),  # a list, not prose
    ('What happened: {"summary": "the model tried JSON anyway"}\nWhy it matters: it is bad really', 0),
    (ANSWER.replace("192.168.1.60", "10.0.0.99"), 0),               # invented address
    (ANSWER.replace("40 times", "4000 times"), 0),                  # invented number
    (ANSWER.replace(WHY, "This is normal for a home network, nothing more."), 0),  # played down
    (ANSWER, 1),                                                    # runner crashed
])
def test_bad_model_output_falls_back_to_templates(llama_cfg, answer, code):
    exp = explain_alert(ALERT, llama_cfg(answer, code))
    assert exp.provider.startswith("template (llama failed")
    assert "192.168.1.60" in exp.summary and exp.facts


def test_long_answer_is_cut_at_a_sentence():
    what, why = parse_output("What happened: " + "The device 192.168.1.60 did something odd. " * 30
                             + "\nWhy it matters: it could be an attack on your network.", "192.168.1.60")
    assert len(what) <= 400 and what.endswith(".")


def test_chatty_preamble_and_markdown_are_removed():
    assert parse_output(f"Here is the explanation: **{ANSWER.replace(chr(10), '** ')}", FACTS) == (WHAT, WHY)


def test_stats_are_stored_and_served(llama_cfg):
    from fastapi.testclient import TestClient

    from netwatch.api import create_app
    c = llama_cfg()
    conn = db.connect(c.db_path)
    upsert(conn, AlertDraft("intrusion", "brute_force", "high", ALERT["title"], "192.168.1.60", "192.168.1.1",
                            1.0, 2.0, ALERT["evidence"]))
    explain_pending(conn, c)
    detail = TestClient(create_app(c)).get("/api/alerts/1").json()
    assert detail["explanation"]["stats"]["decode_token_per_sec"] == 4.0
    assert detail["explanation"]["facts"] and detail["explanation"]["pending"] is False


def test_unexplained_alert_shows_rule_text_while_llama_writes(llama_cfg):
    from fastapi.testclient import TestClient

    from netwatch.api import create_app
    c = llama_cfg()
    conn = db.connect(c.db_path)
    upsert(conn, AlertDraft("intrusion", "brute_force", "high", ALERT["title"], "192.168.1.60", "192.168.1.1",
                            1.0, 2.0, ALERT["evidence"]))
    conn.commit()
    exp = TestClient(create_app(c)).get("/api/alerts/1").json()["explanation"]
    assert exp["pending"] is True and "40 times" in exp["summary"] and exp["actions"]


def test_old_database_gets_new_column(cfg):
    import sqlite3
    raw = sqlite3.connect(cfg.db_path)
    raw.execute("CREATE TABLE explanations (alert_id INTEGER PRIMARY KEY, provider TEXT, model TEXT, summary TEXT,"
                " why TEXT, risk TEXT, actions TEXT, latency_ms INTEGER, created REAL)")
    raw.commit()
    raw.close()
    conn = db.connect(cfg.db_path)
    assert {"stats", "facts"} <= {r["name"] for r in conn.execute("PRAGMA table_info(explanations)")}


def test_stale_explanation_is_dropped_when_severity_rises(cfg, monkeypatch):
    import netwatch.explain as ex
    conn = db.connect(cfg.db_path)
    upsert(conn, AlertDraft("intrusion", "brute_force", "medium", ALERT["title"], "192.168.1.60", "192.168.1.1",
                            1.0, 2.0, ALERT["evidence"]))
    real = ex.explain_alert

    def slow(alert, c):  # severity rises while the model is "running"
        conn.execute("UPDATE alerts SET severity = 'high' WHERE id = ?", (alert["id"],))
        return real(alert, c)
    monkeypatch.setattr(ex, "explain_alert", slow)
    ex.explain_pending(conn, cfg)
    assert conn.execute("SELECT COUNT(*) FROM explanations").fetchone()[0] == 0


def test_explain_worker_runs_beside_detection(llama_cfg):
    from netwatch.pipeline import _explain_worker
    c = llama_cfg()
    conn = db.connect(c.db_path)
    upsert(conn, AlertDraft("intrusion", "brute_force", "high", ALERT["title"], "192.168.1.60", "192.168.1.1",
                            1.0, 2.0, ALERT["evidence"]))
    conn.commit()  # the worker reads on its own connection, as detection commits in live mode
    stop = threading.Event()
    t = threading.Thread(target=_explain_worker, args=(c, 0.1, stop))
    t.start()
    for _ in range(100):
        if conn.execute("SELECT COUNT(*) FROM explanations").fetchone()[0]:
            break
        stop.wait(0.1)
    stop.set()
    t.join(5)
    assert conn.execute("SELECT provider FROM explanations").fetchone()[0] == "llama-executorch"


def test_repeated_labels_are_cut():
    what, why = parse_output(f"{ANSWER} Why it matters: the same thing again, said twice.", FACTS)
    assert why == WHY


def test_facts_never_show_a_rounded_zero_or_a_fake_maker():
    fast = {**ALERT, "evidence": {**ALERT["evidence"], "avg_duration_s": 0.018},
            "devices": {"192.168.1.60": {"hostname": None, "kind": "Phone / tablet",
                                         "vendor": "Private (randomised) MAC"}}}
    text = format_facts(alert_facts(fast))
    assert "0 seconds" not in text and "under a second" in text
    assert "made by" not in text


def test_test_alert_must_not_be_made_to_sound_dangerous():
    facts = "- Background: This is a NetWatch test address. It is not a real threat and nobody is attacking."
    with pytest.raises(ValueError, match="test alert"):
        parse_output("What happened: A phone opened the NetWatch test page on purpose today.\n"
                     "Why it matters: It could mean your network is vulnerable to hacking.", facts)


def test_low_memory_skips_the_model(llama_cfg, monkeypatch):
    c = llama_cfg()
    monkeypatch.setattr("netwatch.explain.llama.MIN_FREE_MB", 10**9)
    exp = explain_alert(ALERT, c)
    assert exp.provider == "template (llama failed: MemoryError)"


def test_resident_runner_keeps_model_loaded(llama_cfg, tmp_path):
    """A fake netwatch_llm speaking the same protocol: two prompts, one load."""
    from netwatch.explain.llama import LlamaExplainer
    c = llama_cfg()
    server = tmp_path / "netwatch_llm"
    server.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('<<<NETWATCH_READY>>>', flush=True)\n"
        "while True:\n"
        "    h = sys.stdin.readline()\n"
        "    if not h: break\n"
        "    sys.stdin.read(int(h))\n"
        f"    print({ANSWER!r} + '<|eot_id|>')\n"
        f"    print('PyTorchObserver ' + {json.dumps(STATS)!r})\n"
        "    print('<<<NETWATCH_END>>>', flush=True)\n")
    server.chmod(0o755)
    LlamaExplainer._instance = None
    ex = LlamaExplainer.get(c)
    assert ex.resident is not None
    for _ in range(2):
        what, why, stats, _ms = ex.write(alert_facts(ALERT))
        assert (what, why) == (WHAT, WHY) and stats["decode_token_per_sec"] == 4.0
    assert ex.resident.loads == 1
    ex.resident.close()
    LlamaExplainer._instance = None


def test_unlabelled_prose_is_split_but_lists_are_refused():
    what, why = parse_output(f"{WHAT} {WHY}", FACTS)
    assert what == WHAT and why == WHY
    with pytest.raises(ValueError, match="list"):
        parse_output("Here's a summary:\n\n* 40 logins\n* from 192.168.1.60", FACTS)


def test_each_task_gets_its_own_example():
    from netwatch.explain.llama import build_prompt
    assert "port scans and a visit to a phishing site" in build_prompt("- x", "summary")
    assert "door camera" not in build_prompt("- x", "alert") and "camera" in build_prompt("- x", "alert")


def test_invented_kind_of_device_is_refused():
    """Seen live: Llama called a Google server 'your camera', a word from its worked example."""
    facts = ("- What NetWatch saw: a laptop on your Wi-Fi (192.168.1.199, made by Intel Corporate) contacted "
             "142.250.134.95 (142.250.134.95) 9 times, once every 43.5 seconds like clockwork\n"
             "- Background: Malware on an infected device often 'phones home' on a fixed clock to ask for orders.")
    with pytest.raises(ValueError, match="kind of device"):
        parse_output("What happened: A laptop (192.168.1.199) contacted your camera (142.250.134.95) 9 times.\n"
                     "Why it matters: It may be infected and asking for orders on a fixed clock.", facts)
    what, _ = parse_output("What happened: A laptop (192.168.1.199) contacted an internet server 9 times.\n"
                           "Why it matters: It may be infected and asking for orders on a fixed clock.", facts)
    assert what.startswith("A laptop")


def test_invented_outcomes_are_refused():
    with pytest.raises(ValueError, match="outcome"):
        parse_output("What happened: A laptop (192.168.1.60) logged in to your router 40 times in a minute.\n"
                     "Why it matters: It turned out to be a false positive and was resolved.", FACTS)
