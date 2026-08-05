"""Tests for individual chain stages and the safe-by-default INFERENCE gate."""

from conftest import FakeSession, resp

from snake_scanner.engine import (
    FAIL,
    GATED,
    OPEN,
    PASS,
    s_auth,
    s_endpoint,
    s_enum,
    s_exploit_surface,
    s_inference,
    s_summary,
)


# ── ENDPOINT ────────────────────────────────────────────────────────────────────
def test_endpoint_prefers_https_and_records_base():
    sess = FakeSession([("GET", "https://", resp(200, headers={"server": "nginx"}))])
    ctx = {}
    r = s_endpoint(sess, "target", 8880, ctx)
    assert r.status == PASS
    assert ctx["scheme"] == "https"
    assert ctx["base"] == "https://target:8880"


def test_endpoint_falls_back_to_http_when_https_dead():
    # https dropped (None), http answers.
    sess = FakeSession([("GET", "https://", None), ("GET", "http://", resp(200))])
    ctx = {}
    r = s_endpoint(sess, "target", 8880, ctx)
    assert r.status == PASS
    assert ctx["scheme"] == "http"


def test_endpoint_fail_when_nothing_answers():
    sess = FakeSession([("GET", "https://", None), ("GET", "http://", None)])
    r = s_endpoint(sess, "target", 8880, {})
    assert r.status == FAIL


# ── AUTH ─────────────────────────────────────────────────────────────────────────
def test_auth_all_open_is_no_auth(base_ctx):
    sess = FakeSession(default=resp(200))  # every probe answers 200
    r = s_auth(sess, "t", 8880, base_ctx)
    assert r.status == OPEN
    assert "NO AUTH" in r.evidence


def test_auth_all_gated_is_enforced(base_ctx):
    sess = FakeSession(default=resp(401))
    r = s_auth(sess, "t", 8880, base_ctx)
    assert r.status == GATED
    assert "AUTH ENFORCED" in r.evidence


def test_auth_mixed_is_partial_open(base_ctx):
    sess = FakeSession(
        rules=[("GET", "/admin", resp(403)), ("GET", "/config", resp(403))],
        default=resp(200),
    )
    r = s_auth(sess, "t", 8880, base_ctx)
    assert r.status == OPEN
    assert "PARTIAL" in r.evidence
    assert "/admin" in r.detail["gated"]


# ── ENUM ─────────────────────────────────────────────────────────────────────────
def test_enum_parses_llm_models(base_ctx):
    sess = FakeSession([("GET", "/v1/models", resp(200, json_data={"data": [{"id": "Qwen2.5-7B"}]}))])
    r = s_enum(sess, "t", 8880, base_ctx)
    assert r.status == PASS
    assert base_ctx["enum"]["llm_models"] == ["Qwen2.5-7B"]


def test_enum_fail_when_nothing_returns_data(base_ctx):
    r = s_enum(FakeSession(), "t", 8880, base_ctx)
    assert r.status == FAIL


# ── INFERENCE (the safe-default gate) ───────────────────────────────────────────
def test_inference_passive_reports_reachable_without_posting(base_ctx):
    base_ctx["active"] = False
    sess = FakeSession([("GET", "/v1/audio/speech", resp(405))])
    r = s_inference(sess, "t", 8880, base_ctx)
    assert r.status == OPEN
    assert "not invoked" in r.evidence
    # No POST may have been issued in passive mode.
    assert all(method != "POST" for method, _ in sess.calls)


def test_inference_active_confirms_tts_via_post(base_ctx):
    base_ctx["active"] = True
    sess = FakeSession([("POST", "/v1/audio/speech", resp(200, content=b"\x00" * 256))])
    r = s_inference(sess, "t", 8880, base_ctx)
    assert r.status == PASS
    assert "TTS synthesis confirmed" in r.evidence
    assert any(method == "POST" for method, _ in sess.calls)


def test_inference_skips_for_pure_infra():
    ctx = {"base": "https://t:9090", "active": True, "service": "prometheus"}
    r = s_inference(FakeSession(), "t", 9090, ctx)
    assert r.status == "SKIP"


# ── EXPLOIT-SURFACE + SUMMARY integration ────────────────────────────────────────
def test_exploit_surface_and_summary_chain_together(base_ctx):
    base_ctx["open_paths"] = ["/v1/models", "/v1/chat/completions"]
    base_ctx["enum"] = {"llm_models": ["gpt"], "health": {"version": "1.0"}}
    base_ctx["adjacent"] = [{"port": 6379}]  # one co-located service
    # openapi.json + network query probes default to 404 -> those surfaces absent.
    sess = FakeSession()
    surface = s_exploit_surface(sess, "t", 8880, base_ctx)
    assert surface.status == OPEN
    assert "COMPUTE-THEFT" in base_ctx["exploit_surfaces"]
    assert "LLM-ABUSE" in base_ctx["exploit_surfaces"]

    summary = s_summary(sess, "t", 8880, base_ctx)
    assert summary.status == OPEN  # open paths present
    rolled = base_ctx["summary"]
    assert {"COMPUTE-THEFT", "LLM-ABUSE"}.issubset(rolled["surfaces"])
    assert "COMPUTE-THEFT" in rolled["high_impact"]        # high-impact surface
    assert "CONFIG-DISCLOSE" not in rolled["high_impact"]  # informational only
    assert rolled["adjacent_count"] == 1
    assert rolled["open_paths"] == ["/v1/models", "/v1/chat/completions"]
