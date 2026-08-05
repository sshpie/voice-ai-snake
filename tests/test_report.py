"""Report-building, persistence, and a full offline run of the whole chain."""

import json
import os

from conftest import FakeSession, resp

from snake_scanner import engine


def _kokoro_session():
    """A coherent fake Kokoro TTS host — enough to drive the whole chain offline."""
    rules = [
        ("GET", "/openapi.json", resp(200, json_data={
            "info": {"title": "Kokoro", "version": "0.19"},
            "paths": {"/v1/audio/speech": {}, "/v1/audio/voices": {}},
        })),
        ("GET", "/v1/audio/voices", resp(200, json_data={"voices": [{"id": "af_bella"}, {"id": "af_sky"}]})),
        ("GET", "/v1/models", resp(200, json_data={"data": [{"id": "kokoro-v1"}]})),
        ("GET", "/health", resp(200, json_data={"version": "0.19", "service": "kokoro"})),
        ("GET", "/speakers", resp(200, json_data={"speakers": ["s1", "s2"]})),
        ("GET", "/v1/audio/speech", resp(405)),  # reachable, POST-only (passive INFERENCE)
        ("GET", "https://target:8880/", resp(200, headers={"server": "uvicorn"}, text="Kokoro")),
    ]
    return FakeSession(rules, default=None)


def test_build_report_has_all_stages_and_schema(snake_tmp_home):
    session = _kokoro_session()
    engine.make_session = lambda: session  # patched for this call
    results, elapsed, service, ctx = engine.run("target", 8880)

    report = engine.build_report("target", 8880, service, results, elapsed, ctx)
    assert report["host"] == "target"
    assert report["port"] == 8880
    assert report["service"] == "kokoro"
    assert report["active"] is False
    assert len(report["stages"]) == len(engine.CHAIN)
    assert {"name", "status", "evidence", "detail"} <= set(report["stages"][0])


def test_full_run_detects_service_and_summarizes(monkeypatch):
    session = _kokoro_session()
    monkeypatch.setattr(engine, "make_session", lambda: session)
    results, elapsed, service, ctx = engine.run("target", 8880)

    assert service == "kokoro"
    assert [r.name for r in results] == engine.STAGE_NAMES
    assert ctx["exploit_surfaces"]           # kokoro exposes surfaces
    assert ctx["summary"]["surfaces"] == ctx["exploit_surfaces"]
    # passive by default: INFERENCE must not have POSTed
    assert all(m != "POST" for m, _ in session.calls)


def test_save_writes_run_file_and_last_json(snake_tmp_home, monkeypatch):
    session = _kokoro_session()
    monkeypatch.setattr(engine, "make_session", lambda: session)
    results, elapsed, service, ctx = engine.run("target", 8880)

    path = engine.save("target", 8880, service, results, elapsed, ctx)
    assert os.path.exists(path)
    assert os.path.exists(os.path.join(str(snake_tmp_home), "last.json"))

    with open(path) as f:
        saved = json.load(f)
    assert saved["service"] == "kokoro"
    assert saved["exploit_surfaces"] == ctx["exploit_surfaces"]
    assert saved["open_paths"] == ctx["open_paths"]


def test_active_flag_recorded_in_report(monkeypatch):
    session = _kokoro_session()
    monkeypatch.setattr(engine, "make_session", lambda: session)
    _, elapsed, service, ctx = engine.run("target", 8880, active=True)
    report = engine.build_report("target", 8880, service, [], elapsed, ctx)
    assert report["active"] is True
