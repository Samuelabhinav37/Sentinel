#!/usr/bin/env python3
"""Structural checks on the LLM triage prompt's injection guard.

No model call -- this proves the guard is present, worded as the corpus
expects, and positioned before any attacker-controlled text, in both
workflow files and in the Python port. Behaviour against a real model is
run_live_check.py (not CI).

Runs under pytest or as a plain script.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from render import (  # noqa: E402
    GUARD, SCHEMA, REPO_ROOT, WORKFLOWS,
    load_build_prompt_jscode, needle_for, render_prompt,
)

PAYLOADS = json.loads((Path(__file__).parent / "payloads.json").read_text(encoding="utf-8"))["payloads"]


def test_workflows_carry_the_guard_and_schema_verbatim():
    for wf in WORKFLOWS:
        js = load_build_prompt_jscode(REPO_ROOT / wf)
        assert GUARD in js, f"{wf}: guard sentence missing or reworded"
        assert SCHEMA in js, f"{wf}: schema line missing or reworded"
        assert "ONLY a single JSON object" in js, wf


def test_guard_precedes_untrusted_data_in_workflows():
    for wf in WORKFLOWS:
        js = load_build_prompt_jscode(REPO_ROOT / wf)
        assert js.index(GUARD) < js.index("'Alert:'"), wf
        assert js.index("'Alert:'") < js.index("Raw fields (truncated): "), wf


def test_python_port_matches_that_ordering():
    p = render_prompt(description="benign")
    assert p.index(SCHEMA) < p.index(GUARD) < p.index("\nAlert:") < p.index("Raw fields (truncated): ")


def test_every_payload_lands_after_the_guard():
    clean = render_prompt()
    prefix = clean[: clean.index(GUARD)]
    for pl in PAYLOADS:
        field, payload = pl["field"], pl["payload"]
        kw = {"rule_name": "Netcat reverse shell", "host": "web-01", "description": ""}
        alert = {"process": {"name": "nc", "pid": 4321}}
        if field == "raw":
            alert["cmdline"] = payload
        else:
            kw[field] = payload
        p = render_prompt(alert=alert, **kw)

        needle = needle_for(field, payload)
        assert needle in p, f"{pl['id']}: payload not found in rendered prompt"
        assert p.index(needle) > p.index(GUARD), f"{pl['id']}: payload appears before the guard"
        assert p[: p.index(GUARD)] == prefix, f"{pl['id']}: payload changed the pre-guard preamble"


def test_payload_file_is_wellformed():
    ids = set()
    for pl in PAYLOADS:
        assert {"id", "field", "payload", "intent", "live_assert"} <= set(pl), pl
        assert pl["field"] in {"rule_name", "host", "description", "raw"}, pl
        assert pl["id"] not in ids, f"duplicate id {pl['id']}"
        ids.add(pl["id"])


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e}")
    print("PASS" if not failed else f"{failed} FAILED")
    sys.exit(1 if failed else 0)
