"""Tests for the hybrid risk-score fusion engine."""

from app.fusion import fuse, classify
from app.schemas import HeuristicResult, MLResult, ReputationSummary


def _reputation(verdict="safe", score=0, unavailable=False, block=False):
    # An unavailable provider reports verdict "unavailable" (never a safe vote).
    v = "unavailable" if unavailable else verdict
    return ReputationSummary(
        verdict=v,
        block=block,
        score=score,
        providers=[],
        consensus={"votes": {"safe": 0, "suspicious": 0, "malicious": 0}, "available": 0, "total": 0},
        errors=[],
        source="test",
        partial=False,
        unavailable=unavailable,
    )


def test_safe_all_clear():
    h = HeuristicResult(verdict="safe", score=0, signals=[], source="local")
    m = MLResult(prediction="safe", probability=0.05, available=True)
    r = _reputation("safe", 0)
    res = fuse(h, m, r)
    assert res["verdict"] == "safe"
    assert res["classification"] == "Safe"
    assert res["risk_score"] < 35


def test_strong_local_malicious_reaches_malicious():
    # Heuristic score 100 (existing malicious) -> local evidence reaches Malicious.
    h = HeuristicResult(verdict="malicious", score=100, signals=["Raw IP address"], source="local")
    m = MLResult(prediction="safe", probability=0.05, available=True)
    r = _reputation("safe", 0)
    res = fuse(h, m, r)
    assert res["verdict"] == "malicious"
    assert res["risk_score"] >= 70


def test_unavailable_reputation_not_auto_safe():
    h = HeuristicResult(verdict="suspicious", score=40, signals=["Sensitive keyword"], source="local")
    m = MLResult(prediction="suspicious", probability=0.5, available=True)
    r = _reputation(unavailable=True)
    res = fuse(h, m, r)
    # Local risk present; reputation unavailable must not force a Safe verdict.
    assert res["verdict"] == "suspicious"
    assert res["risk_score"] >= 35


def test_no_available_evidence_uses_local():
    h = HeuristicResult(verdict="safe", score=0, signals=[], source="local")
    m = MLResult(prediction="safe", probability=0.05, available=False)
    r = _reputation(unavailable=True)
    res = fuse(h, m, r)
    # Local heuristic is the only usable evidence; it says safe, so Safe is correct
    # (driven by local evidence, not by an unavailable API).
    assert res["verdict"] == "safe"
    assert res["confidence"] == "low"


def test_classify_thresholds():
    assert classify(0) == "Safe"
    assert classify(34) == "Safe"
    assert classify(35) == "Suspicious"
    assert classify(69) == "Suspicious"
    assert classify(70) == "Malicious"
    assert classify(100) == "Malicious"


def test_no_double_counting_correlated():
    # heuristic and ML both say malicious; reputation says safe.
    h = HeuristicResult(verdict="malicious", score=80, signals=[], source="local")
    m = MLResult(prediction="malicious", probability=0.9, available=True)
    r = _reputation("safe", 0)
    res = fuse(h, m, r)
    # Correlated layer uses max(h,p), not sum: max(0.8, 0.9)=0.9 -> 68 points,
    # not 80+90. Verdict Suspicious (needs >=70 for Malicious).
    assert res["risk_score"] == 68
    assert res["verdict"] == "suspicious"
    assert res["risk_score"] <= 100

