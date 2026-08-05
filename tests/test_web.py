"""Integration tests for the web transport layer (no real network).

Uses FastAPI's TestClient and a monkeypatched stream so the SSE wiring is
exercised without probing anything.
"""

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from snake_scanner import web  # noqa: E402
from snake_scanner.engine import PASS, STAGE_NAMES, StageResult  # noqa: E402


@pytest.fixture
def client():
    return TestClient(web.app)


def test_index_serves_page_with_injected_stage_names(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "VOICE AI VERIFICATION SNAKE" in r.text
    # stage list injected from the engine, not hard-coded in the template
    assert "__STAGE_NAMES__" not in r.text
    for name in STAGE_NAMES:
        assert name in r.text


def test_run_streams_sse_frames(client, monkeypatch, snake_tmp_home):
    def fake_stream(host, port, service="auto", active=False):
        ctx = {"open_paths": ["/v1/models"],
               "exploit_surfaces": ["COMPUTE-THEFT"],
               "adjacent": [{"port": 6379}]}
        yield StageResult("ENDPOINT", PASS, "https 200"), service, ctx
        yield None, "kokoro", ctx  # service-detected sentinel
        yield StageResult("SUMMARY", PASS, "1 path(s) open without auth"), "kokoro", ctx

    monkeypatch.setattr(web, "run_stream", fake_stream)

    r = client.get("/run", params={"host": "t", "port": 8880})
    assert r.status_code == 200
    body = r.text
    assert 'data: {"type": "service"' in body
    assert '"type": "stage"' in body
    assert '"type": "complete"' in body
    assert "COMPUTE-THEFT" in body
