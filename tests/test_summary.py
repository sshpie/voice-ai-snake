"""Tests for the pure summary roll-up — the chain's final verdict, network-free.

summarize() takes no session and touches no network, so it is exhaustively
testable. It reports *what was found* (open paths, classified surfaces, adjacent
services) with no score and no severity tier.
"""

from snake_scanner.engine import HIGH_IMPACT_SURFACES, summarize


def test_empty_summary_has_no_exposure():
    s = summarize([], [], 0)
    assert s["open_paths"] == []
    assert s["surfaces"] == []
    assert s["high_impact"] == []
    assert s["adjacent_count"] == 0


def test_high_impact_is_filtered_subset_of_surfaces():
    s = summarize(["COMPUTE-THEFT", "CONFIG-DISCLOSE"], ["/v1/models"], 2)
    assert s["surfaces"] == ["COMPUTE-THEFT", "CONFIG-DISCLOSE"]
    assert s["high_impact"] == ["COMPUTE-THEFT"]  # CONFIG-DISCLOSE is informational
    assert s["open_paths"] == ["/v1/models"]
    assert s["adjacent_count"] == 2


def test_config_and_content_leaks_alone_are_not_high_impact():
    s = summarize(["CONFIG-DISCLOSE", "CONTENT-LEAK", "TOPOLOGY-LEAK"], [], 0)
    assert s["high_impact"] == []
    assert set(HIGH_IMPACT_SURFACES).isdisjoint(s["surfaces"])


def test_summarize_snapshots_inputs_rather_than_aliasing():
    surfaces = ["LLM-ABUSE"]
    opens = ["/x"]
    s = summarize(surfaces, opens, 0)
    surfaces.append("MUTATED")
    opens.append("/y")
    assert s["surfaces"] == ["LLM-ABUSE"]  # snapshot, not a live reference
    assert s["open_paths"] == ["/x"]
