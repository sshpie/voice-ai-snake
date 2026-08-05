"""Tests for service auto-detection and its specificity ordering."""

from conftest import FakeSession, resp

from snake_scanner.engine import detect


def _detect_with(rules):
    ctx = {"base": "https://target:8880"}
    return detect(FakeSession(rules), "target", 8880, ctx)


def test_kokoro_detected_from_voice_list():
    assert _detect_with([("GET", "/v1/audio/voices", resp(200, text="af_bella af_sky"))]) == "kokoro"


def test_prometheus_detected_from_active_targets():
    assert _detect_with([("GET", "/api/v1/targets", resp(200, text='{"activeTargets": []}'))]) == "prometheus"


def test_unknown_service_falls_back_to_generic():
    # default route is 404, so nothing matches.
    assert _detect_with([]) == "generic"


def test_specificity_order_kokoro_wins_over_prometheus():
    # A host answering BOTH a kokoro signal and a prometheus signal must be
    # classified kokoro, because the specific voice fingerprint precedes the
    # generic /metrics-bearing prometheus check.
    rules = [
        ("GET", "/v1/audio/voices", resp(200, text="af_bella")),
        ("GET", "/api/v1/targets", resp(200, text='{"activeTargets": []}')),
    ]
    assert _detect_with(rules) == "kokoro"


def test_status_must_be_200_to_match():
    # keyword present but behind a 500 must NOT classify.
    assert _detect_with([("GET", "/v1/audio/voices", resp(500, text="af_bella"))]) == "generic"
