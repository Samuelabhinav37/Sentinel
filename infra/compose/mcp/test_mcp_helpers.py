#!/usr/bin/env python3
"""Unit tests for the Sentinel MCP server's guard rails.

Runs under pytest (CI, after `pip install -r requirements.txt`) or as a
plain script. Covers the parts that keep a token holder from turning the
MCP server into a cluster-wide search passthrough or a quiet way to fire
the response gate: the index allowlist, the search-size clamp, doc-by-id
lookups, and the human_confirmed guard on trigger_shuffle_response. No
network: _elastic_request and the HTTP client are patched out.
"""
import contextlib
import os
import sys

os.environ.setdefault("MCP_TOKEN", "test-token")
os.environ.setdefault("ELASTIC_URL", "http://localhost:9200")
os.environ.setdefault("ELASTIC_PASSWORD", "test")
os.environ.setdefault("WAZUH_API_URL", "http://localhost:55000")
os.environ.setdefault("WAZUH_API_PASSWORD", "test")
os.environ.setdefault("SHUFFLE_WEBHOOK_URL", "http://localhost/webhook")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mcp_server as m  # noqa: E402


@contextlib.contextmanager
def patch(obj, name, value):
    sentinel = object()
    old = getattr(obj, name, sentinel)
    setattr(obj, name, value)
    try:
        yield
    finally:
        if old is sentinel:
            delattr(obj, name)
        else:
            setattr(obj, name, old)


class Recorder:
    """Stands in for _elastic_request: records the last call, returns a
    canned response."""

    def __init__(self, response=None):
        self.response = response if response is not None else {"hits": {"hits": []}}
        self.calls = []

    def __call__(self, path, method="GET", body=None):
        self.calls.append((path, method, body))
        return self.response

    @property
    def last_body(self):
        return self.calls[-1][2]


# ---------------------------------------------------------------- allowlist

def test_index_allowlist_accepts_known_patterns():
    for ok in (
        "sentinel-triage",
        "sentinel-response-actions",
        "winlogbeat-ecs-000001",
        "auditbeat-linux",
        ".alerts-security.alerts-default-000001",
    ):
        assert m._index_allowed(ok) is True, ok


def test_index_allowlist_rejects_everything_else():
    for bad in (".kibana", "logs-*", "*", "", "sentinel-secrets", "../../etc"):
        assert m._index_allowed(bad) is False, bad


def test_index_allowlist_rollover_backing_index_is_a_known_gap():
    # Once sentinel-triage rolls over, its backing index is
    # "sentinel-triage-000001", which the bare "sentinel-triage" allowlist
    # entry does NOT match. Callers use the alias, so this is currently
    # harmless -- if the allowlist is widened to "sentinel-triage*", flip
    # this assertion.
    assert m._index_allowed("sentinel-triage-000001") is False


# ------------------------------------------------------------- _range_query

def test_range_query_no_query_no_times_is_match_all():
    assert m._range_query("", None, None) == {"match_all": {}}


def test_range_query_query_only():
    assert m._range_query("host:web1", None, None) == {"query_string": {"query": "host:web1"}}


def test_range_query_with_time_bounds():
    q = m._range_query("x", "2026-01-01", "2026-02-01")
    rng = q["bool"]["filter"][0]["range"]["@timestamp"]
    assert rng == {"gte": "2026-01-01", "lte": "2026-02-01"}
    assert q["bool"]["must"] == [{"query_string": {"query": "x"}}]


# ------------------------------------------------------------ _get_doc_by_id

def test_get_doc_by_id_returns_shaped_hit_and_uses_search():
    rec = Recorder({"hits": {"hits": [{"_index": "sentinel-triage-000001",
                                       "_id": "abc", "_source": {"severity": "high"}}]}})
    with patch(m, "_elastic_request", rec):
        doc = m._get_doc_by_id("sentinel-triage", "abc")
    assert doc == {"_index": "sentinel-triage-000001", "_id": "abc",
                   "found": True, "_source": {"severity": "high"}}
    path, method, body = rec.calls[-1]
    assert path == "sentinel-triage/_search" and method == "POST"
    assert body == {"query": {"term": {"_id": "abc"}}, "size": 1}


def test_get_doc_by_id_raises_when_no_hits():
    with patch(m, "_elastic_request", Recorder({"hits": {"hits": []}})):
        try:
            m._get_doc_by_id("sentinel-triage", "missing")
        except m._DocNotFound:
            pass
        else:
            raise AssertionError("expected _DocNotFound")


def test_get_triage_translates_not_found_to_error_dict():
    def boom(index, doc_id):
        raise m._DocNotFound(doc_id)

    with patch(m, "_get_doc_by_id", boom):
        out = m.get_triage("nope")
    assert out == {"error": "no triage doc found for alert_id nope"}


# --------------------------------------------------------------- size clamp

def test_search_index_rejects_non_allowlisted_without_touching_es():
    rec = Recorder()
    with patch(m, "_elastic_request", rec):
        out = m.search_index(".kibana")
    assert "error" in out
    assert rec.calls == []  # never reached Elasticsearch


def test_search_index_clamps_oversized_size():
    rec = Recorder({"hits": {"hits": []}})
    with patch(m, "_elastic_request", rec):
        m.search_index("sentinel-triage", size=9999)
    assert rec.last_body["size"] == m.MAX_SEARCH_SIZE


def test_search_index_clamps_nonpositive_size_to_one():
    rec = Recorder({"hits": {"hits": []}})
    with patch(m, "_elastic_request", rec):
        m.search_index("sentinel-triage", size=0)
    assert rec.last_body["size"] == 1


def test_search_alerts_clamps_size_and_targets_alerts_index():
    rec = Recorder({"hits": {"hits": []}})
    with patch(m, "_elastic_request", rec):
        m.search_alerts(size=10_000)
    path, _, body = rec.calls[-1]
    assert path == ".alerts-security.alerts-default*/_search"
    assert body["size"] == m.MAX_SEARCH_SIZE


# ------------------------------------------------------ agreement lookup

def test_triage_is_actionable():
    assert m._triage_is_actionable({"severity": "high", "false_positive_likelihood": "low"}) is True
    assert m._triage_is_actionable({"severity": "CRITICAL", "false_positive_likelihood": "Low"}) is True
    assert m._triage_is_actionable({"severity": "medium", "false_positive_likelihood": "low"}) is False
    assert m._triage_is_actionable({"severity": "high", "false_positive_likelihood": "medium"}) is False
    assert m._triage_is_actionable({}) is False
    assert m._triage_is_actionable(None) is False


ACT = {"severity": "high", "false_positive_likelihood": "low"}


def test_dual_model_agrees_true_when_record_shows_both_models_actionable():
    doc = {"_source": {"cross_check_agreement": True, "triage": ACT, "triage_secondary": dict(ACT)}}
    with patch(m, "_get_doc_by_id", lambda idx, did: doc):
        ok, why = m._dual_model_agrees("a1")
    assert ok is True and why == ""


def test_dual_model_agrees_false_when_no_push_record():
    def missing(idx, did):
        raise m._DocNotFound(did)

    with patch(m, "_get_doc_by_id", missing):
        ok, why = m._dual_model_agrees("a1")
    assert ok is False and "a1-push" in why


def test_dual_model_agrees_false_when_flag_not_true():
    doc = {"_source": {"cross_check_agreement": False, "triage": ACT, "triage_secondary": dict(ACT)}}
    with patch(m, "_get_doc_by_id", lambda idx, did: doc):
        ok, why = m._dual_model_agrees("a1")
    assert ok is False and "cross_check_agreement" in why


def test_dual_model_agrees_false_when_one_model_not_actionable():
    doc = {"_source": {"cross_check_agreement": True, "triage": ACT,
                       "triage_secondary": {"severity": "medium", "false_positive_likelihood": "low"}}}
    with patch(m, "_get_doc_by_id", lambda idx, did: doc):
        ok, why = m._dual_model_agrees("a1")
    assert ok is False and "both models" in why


def test_dual_model_agrees_fails_closed_on_lookup_error():
    def boom(idx, did):
        raise RuntimeError("ES down")

    with patch(m, "_get_doc_by_id", boom):
        ok, why = m._dual_model_agrees("a1")
    assert ok is False and "could not read" in why


# ------------------------------------------------ trigger_shuffle_response

class _RecordingClient:
    def __init__(self):
        self.posted = None

    def post(self, url, json=None, timeout=None):
        self.posted = {"url": url, "json": json}

        class R:
            status_code = 200
            text = "ok"

        return R()


def test_trigger_refuses_without_agreement_or_human_confirmed():
    client = _RecordingClient()
    with patch(m, "_dual_model_agrees", lambda aid: (False, "no record")), patch(m, "_http_client", client):
        out = m.trigger_shuffle_response(pid=42, reason="x", alert_id="a", human_confirmed=False)
    assert "error" in out
    assert client.posted is None


def test_trigger_proceeds_on_agreement_without_human_confirmed():
    client = _RecordingClient()
    with patch(m, "_dual_model_agrees", lambda aid: (True, "")), patch(m, "_http_client", client):
        out = m.trigger_shuffle_response(pid=42, reason="rev shell", alert_id="a1", human_confirmed=False)
    assert client.posted["json"] == {"pid": 42, "reason": "rev shell", "alert_id": "a1"}
    assert out == {"status": 200, "body": "ok", "gate": "cross_check_agreement"}


def test_trigger_proceeds_on_human_override_when_no_agreement():
    client = _RecordingClient()
    with patch(m, "_dual_model_agrees", lambda aid: (False, "no record")), patch(m, "_http_client", client):
        out = m.trigger_shuffle_response(pid=42, reason="x", alert_id="a", human_confirmed=True)
    assert client.posted is not None
    assert out["gate"] == "human_override"


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
