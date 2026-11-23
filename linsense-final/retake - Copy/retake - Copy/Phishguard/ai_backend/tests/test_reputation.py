"""Tests for reputation aggregation and normalization semantics."""

from app.reputation import aggregate_results
from app.schemas import ProviderResult


def test_aggregate_all_unavailable():
    results = [
        ProviderResult(name="A", available=False, verdict=None, error="down"),
        ProviderResult(name="B", available=False, verdict=None, error="timeout"),
    ]
    out = aggregate_results(results)
    assert out["verdict"] == "unavailable"
    assert out["unavailable"] is True
    assert out["block"] is False
    assert out["consensus"]["available"] == 0
    assert "down" in " ".join(out["errors"])


def test_aggregate_majority_and_risk_block():
    results = [
        ProviderResult(name="A", available=True, verdict="safe"),
        ProviderResult(name="B", available=True, verdict="suspicious"),
        ProviderResult(name="C", available=True, verdict="safe"),
    ]
    out = aggregate_results(results)
    assert out["consensus_verdict"] == "safe"
    assert out["risk_verdict"] == "suspicious"
    assert out["block"] is True
    assert out["unavailable"] is False


def test_aggregate_tie_breaks_to_severe():
    results = [
        ProviderResult(name="A", available=True, verdict="safe"),
        ProviderResult(name="B", available=True, verdict="malicious"),
    ]
    out = aggregate_results(results)
    assert out["consensus_verdict"] == "malicious"
    assert out["risk_verdict"] == "malicious"
    assert out["block"] is True


def test_unavailable_not_counted_as_safe():
    results = [
        ProviderResult(name="A", available=True, verdict="suspicious"),
        ProviderResult(name="B", available=False, verdict=None, error="no key"),
    ]
    out = aggregate_results(results)
    assert out["consensus"]["available"] == 1
    assert out["consensus_verdict"] == "suspicious"
    assert out["block"] is True
