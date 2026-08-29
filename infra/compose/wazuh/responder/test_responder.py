#!/usr/bin/env python3
"""Unit tests for the responder's kill-decision logic.

Runs under pytest (CI) or as a plain script (`python test_responder.py`).
Only `evaluate_kill` is exercised here -- it is the security-relevant part
(pid validation + the protected-process allowlist) and is pure, so it
needs no socket, no /proc, and never calls os.kill.
"""
import os
import sys

os.environ.setdefault("RESPONDER_TOKEN", "test-token")
os.environ.setdefault("ELASTIC_URL", "http://localhost:9200")
os.environ.setdefault("ELASTIC_PASSWORD", "test")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import responder  # noqa: E402

NEVER_CALLED = lambda pid: (_ for _ in ()).throw(AssertionError("read_comm must not be called"))  # noqa: E731


def _alive(comm):
    return lambda pid: comm


def test_none_pid_rejected_before_proc_lookup():
    d = responder.evaluate_kill(None, read_comm_fn=NEVER_CALLED)
    assert d.proceed is False
    assert d.http_status == 400
    assert d.log_detail == "missing/invalid pid"
    assert d.client_detail == "missing/invalid pid"
    assert d.comm is None  # handler keys off this to skip entry["comm"]


def test_pid_one_and_below_rejected():
    for raw in (1, 0, -5):
        d = responder.evaluate_kill(raw, read_comm_fn=NEVER_CALLED)
        assert d.proceed is False and d.http_status == 400, raw


def test_bool_pid_rejected():
    # isinstance(True, int) is True in Python; a bool must never be a pid.
    for raw in (True, False):
        d = responder.evaluate_kill(raw, read_comm_fn=NEVER_CALLED)
        assert d.proceed is False and d.http_status == 400, raw


def test_non_numeric_string_rejected():
    d = responder.evaluate_kill("not-a-pid", read_comm_fn=NEVER_CALLED)
    assert d.proceed is False and d.http_status == 400


def test_numeric_string_is_coerced():
    d = responder.evaluate_kill("4321", read_comm_fn=_alive("python3"))
    assert d.proceed is True
    assert d.pid == 4321 and isinstance(d.pid, int)
    assert d.comm == "python3"


def test_process_not_found():
    d = responder.evaluate_kill(4321, read_comm_fn=_alive(""))
    assert d.proceed is False
    assert d.http_status == 404
    assert d.log_detail == "process not found"
    assert d.comm == ""  # distinct from None: handler records comm="" here
    assert d.pid == 4321


def test_every_protected_comm_is_refused():
    for comm in responder.PROTECTED_COMMS:
        d = responder.evaluate_kill(9999, read_comm_fn=_alive(comm))
        assert d.proceed is False, comm
        assert d.http_status == 403, comm
        assert d.log_detail == "protected process"
        assert comm in d.client_detail  # caller is told which one
        assert d.comm == comm


def test_ordinary_process_proceeds():
    d = responder.evaluate_kill(31337, read_comm_fn=_alive("nc"))
    assert d.proceed is True
    assert d.http_status == 200
    assert d.pid == 31337
    assert d.comm == "nc"
    assert d.log_detail == "" and d.client_detail == ""


def test_protected_check_is_exact_match_not_substring():
    # "sshd-session" is not "sshd"; the allowlist is a set, membership is exact.
    d = responder.evaluate_kill(9999, read_comm_fn=_alive("sshd-session"))
    assert d.proceed is True


def test_recent_kill_count_missing_file_is_zero():
    assert responder.recent_kill_count(path="/no/such/file", window_minutes=60) == 0


def test_recent_kill_count_filters_by_window_result_and_shape(tmp_path=None):
    if tmp_path is None:
        return  # needs pytest's tmp_path fixture
    import json as _json
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

    def ago(mins):
        return (now - timedelta(minutes=mins)).isoformat()

    path = os.path.join(str(tmp_path), "actions.jsonl")
    with open(path, "w") as f:
        for row in [
            {"result": "killed", "@timestamp": ago(5)},              # counts
            {"result": "kill-unconfirmed", "@timestamp": ago(30)},   # counts
            {"result": "killed", "@timestamp": ago(120)},            # outside 60m
            {"result": "rejected", "@timestamp": ago(1)},            # not a kill
            {"result": "killed"},                                    # no timestamp
            {"not": "the expected shape"},                           # ignored
        ]:
            f.write(_json.dumps(row) + "\n")
        f.write("{ not valid json at all\n")                         # ignored

    assert responder.recent_kill_count(path=path, window_minutes=60, now=now) == 2
    assert responder.recent_kill_count(path=path, window_minutes=180, now=now) == 3


def test_confirm_gone_true_when_process_already_absent():
    assert responder.confirm_gone(4321, read_comm_fn=lambda p: "", delay=0) is True


def test_confirm_gone_rechecks_after_delay():
    seq = iter(["python3", ""])  # present, then gone
    assert responder.confirm_gone(4321, read_comm_fn=lambda p: next(seq), delay=0) is True


def test_confirm_gone_false_when_still_present():
    assert responder.confirm_gone(4321, read_comm_fn=lambda p: "python3", delay=0) is False


def test_breaker_constants_have_sane_defaults():
    assert responder.RESPONDER_MAX_KILLS >= 1
    assert responder.RESPONDER_WINDOW_MINUTES >= 1


def test_main_refuses_to_start_without_env(monkeypatch=None):
    # Only meaningful under pytest (monkeypatch); skipped in script mode.
    if monkeypatch is None:
        return
    monkeypatch.delenv("RESPONDER_TOKEN", raising=False)
    try:
        responder.main()
    except SystemExit as e:
        assert "RESPONDER_TOKEN" in str(e)
    else:  # pragma: no cover
        raise AssertionError("main() should have exited")


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
