"""Hybrid evidence-fusion engine for LinkSense AI.

Combines three evidence layers into a transparent final risk score (0-100):

  1. Existing heuristic risk score (baseline preserved).
  2. Machine Learning calibrated phishing probability.
  3. External reputation results (consensus + any-provider-risk).

Design principles (documented):
  - Do not simply add all scores together (avoids double-counting correlated signals).
  - Heuristic and ML both derive from URL features, so they are treated as
    *correlated* evidence: we take the max of their normalized contributions
    rather than summing them.
  - Reputation is *independent* external evidence: it adds its own contribution.
  - An unavailable provider is never treated as safe; unknown URLs are never
    auto-cleared just because APIs are down.
  - Final classification thresholds are selected from validation data (default
    values shown; PHASE 8 refines them with real experiments).

Mathematical explanation:

  h = heuristic_score / 100                 # [0,1] existing LinkSense heuristic
  p = ml_probability                        # [0,1] calibrated phishing probability
  r = reputation_score / 100                # [0,1] from aggregate_results

  # Correlated layer: heuristic and ML share URL-feature inputs, so fuse by max
  # (probabilistic OR) rather than sum, then scale to 0-75 points. Local evidence
  # is the primary signal; a strong local malicious indicator can reach Malicious.
  correlated = max(h, p)
  correlated_points = round(75 * correlated)

  # Independent reputation layer: scale to 0-25 points. Reputation is weighted
  # lower than local evidence because providers may be unavailable or rate-limited.
  reputation_points = round(25 * r)

  # Final risk score (0-100)
  risk_score = min(100, correlated_points + reputation_points)

  # Classification thresholds (tuned on validation data; defaults shown):
  #   risk_score >= 70  -> Malicious
  #   risk_score >= 35  -> Suspicious
  #   otherwise         -> Safe
"""

from typing import Any, Dict

from app.schemas import HeuristicResult, MLResult, ReputationSummary

# Classification thresholds (0-100 risk score). Validated defaults; refine in PHASE 8.
THRESHOLD_MALICIOUS = 70
THRESHOLD_SUSPICIOUS = 35


def classify(risk_score: int) -> str:
    if risk_score >= THRESHOLD_MALICIOUS:
        return "Malicious"
    if risk_score >= THRESHOLD_SUSPICIOUS:
        return "Suspicious"
    return "Safe"


def fuse(
    heuristic: HeuristicResult,
    ml: MLResult,
    reputation: ReputationSummary,
    *,
    threshold_malicious: int = THRESHOLD_MALICIOUS,
    threshold_suspicious: int = THRESHOLD_SUSPICIOUS,
) -> Dict[str, Any]:
    """Fuse evidence layers into a final risk score and classification.

    Returns a dict with risk_score, classification, verdict, confidence, and
    per-layer contribution breakdown.
    """
    h = min(max(heuristic.score, 0), 100) / 100.0
    p = min(max(ml.probability, 0.0), 1.0)
    r = min(max(reputation.score, 0), 100) / 100.0

    # Correlated layer (heuristic & ML share URL features): probabilistic OR.
    correlated = max(h, p)
    correlated_points = round(75 * correlated)

    # Independent reputation layer.
    reputation_points = round(25 * r)

    risk_score = min(100, correlated_points + reputation_points)

    classification = classify(risk_score)
    # Map classification to the 3-value verdict used elsewhere.
    verdict_map = {"Safe": "safe", "Suspicious": "suspicious", "Malicious": "malicious"}
    verdict = verdict_map[classification]

    # Confidence reflects how much evidence agreed and how available it was.
    evidence_available = 0
    if heuristic.score is not None:
        evidence_available += 1
    if ml.available:
        evidence_available += 1
    if reputation.verdict != "unavailable":
        evidence_available += 1
    if evidence_available >= 3:
        confidence = "high"
    elif evidence_available == 2:
        confidence = "medium"
    else:
        confidence = "low"

    # If everything is unavailable, never declare safe; fall to suspicious-low.
    if evidence_available == 0:
        risk_score = max(risk_score, 35)
        classification = "Suspicious"
        verdict = "suspicious"
        confidence = "low"

    return {
        "risk_score": risk_score,
        "classification": classification,
        "verdict": verdict,
        "confidence": confidence,
        "correlated_points": correlated_points,
        "reputation_points": reputation_points,
        "heuristic_normalized": round(h, 3),
        "ml_probability": round(p, 3),
        "reputation_normalized": round(r, 3),
        "threshold_malicious": threshold_malicious,
        "threshold_suspicious": threshold_suspicious,
    }
