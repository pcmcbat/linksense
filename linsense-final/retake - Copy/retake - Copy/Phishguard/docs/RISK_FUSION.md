# Risk Fusion & Scoring (Implemented)

## Evidence layers
1. **Heuristic (baseline, preserved):** `app.heuristic.analyze_url_locally` / extension local analyzer produce 0–100 score, verdict, signals.
2. **ML (optional):** calibrated phishing probability `p ∈ [0,1]` from `ml.predict` when model artifacts are available; otherwise unavailable.
3. **Reputation (independent):** aggregated provider score/verdict from `app.reputation` (unavailable providers never treated as safe).

## Feature extraction (`app.features`)
Fixed schema (`FEATURE_NAMES`) used consistently for training/inference: URL/domain lengths, subdomain/dot/hyphen/digit/special counts, suspicious keyword count, HTTPS, IP host, punycode, URL encoding, unusual port, embedded credentials, path length/query count/path depth, brand indicator/edit-distance signal, URL shortener.

## Fusion math (`app.fusion`)
Correlated local evidence is not naively summed (heuristic and ML share URL-derived signals):

- `h = clamp(heuristic_score, 0..100) / 100`
- `p = clamp(ml_probability, 0..1)`
- `r = clamp(reputation_score, 0..100) / 100`
- `correlated = max(h, p)`
- `correlated_points = round(75 * correlated)`
- `reputation_points = round(25 * r)`
- `risk_score = min(100, correlated_points + reputation_points)`

## Classification thresholds (current defaults)
- `risk_score >= 70` → **Malicious**
- `risk_score >= 35` → **Suspicious**
- otherwise → **Safe**

These are transparent defaults in code and **must be validated/calibrated on real validation data** before research claims.

## Confidence
Derived from available evidence layers (heuristic, ML available, reputation not unavailable): high/medium/low. If no evidence is available, the system avoids declaring safe by defaulting to low-confidence suspicious handling in fusion.

## Explanation policy (`app.explain`)
- Evidence-grounded summary (heuristic signals, ML probability, provider findings, recommended action).
- LLM-backed explanation is optional and backend-only; deterministic fallback when unavailable.
- **Explanation never overrides verdict.** External/URL/provider text treated as untrusted input and sanitized.

## Limitations
- Probabilities are model estimates (when available), not guaranteed attack probabilities.
- Default thresholds/weights require empirical validation and possible recalibration.
- Provider scores/coverage vary by URL/domain/IP and API availability.
