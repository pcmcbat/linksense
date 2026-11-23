"""Tests for deterministic explanation generation and verdict preservation."""

import asyncio

from app.explain import _fallback_explanation, recommended_action
from app.schemas import HeuristicResult, MLResult, ReputationSummary


def _rep():
    return ReputationSummary(
        verdict="safe",
        block=False,
        score=0,
        providers=[],
        consensus={"votes": {"safe": 0, "suspicious": 0, "malicious": 0}, "available": 0, "total": 0},
        errors=[],
        source="test",
        partial=False,
        unavailable=True,
    )


def test_recommended_action_mapping():
    assert "Avoid" in recommended_action("malicious")
    assert "caution" in recommended_action("suspicious").lower()
    assert "No specific" in recommended_action("safe")


def test_fallback_explanation_does_not_embed_raw_credentials():
    h = HeuristicResult(verdict="safe", score=0, signals=[], source="local")
    m = MLResult(prediction="safe", probability=0.1, available=False, error="unavailable")
    r = _rep()
    fused = {"verdict": "safe", "risk_score": 10, "confidence": "low"}
    text = _fallback_explanation("https://user:secret@example.com/path?q=1", h, m, r, fused)
    assert "secret" not in text
    assert "Risk score" in text or "risk score" in text
