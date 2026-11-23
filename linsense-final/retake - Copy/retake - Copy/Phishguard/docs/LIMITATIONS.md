# Limitations, Security Notes, and Future Work

## Implemented vs pending (high level)
- **Implemented (scaffold/partial):** baseline extension flow preserved, legacy Node reputation backend, FastAPI hybrid API (`/scan`, `/api/scan`, `/api/explain`, `/health`, `/api/model/info`, `/api/scan/history`), heuristic/feature pipeline, fusion engine, deterministic explanation (+ optional LLM hook), provider adapters/aggregation, popup surfacing of AI fields, automated pytest coverage for core behaviors.
- **Pending/incomplete:** real dataset-backed training & calibrated artifacts, validated thresholds from experiments, full comparative/ablation/robustness/latency evaluation with actual results and graphs, broader end-to-end/regression automation, production-grade hardening and persistence, complete academic report assets from measured outcomes.

## ML and evaluation limitations
- No trained `model.joblib`/`model_meta.json` or labeled dataset is included; ML predictions are unavailable until artifacts are supplied.
- No accuracy/PR-AUC/ROC-AUC/calibration/latency figures are reported because no real experiments have been executed here (and must not be fabricated).
- Default fusion thresholds/weights and model calibration require validation on representative, leakage-controlled datasets.

## Threat-intelligence limitations
- Provider verdicts depend on external APIs, keys, quotas, coverage, and timeliness; unavailable results are not safe signals.
- Some providers are domain- or IP-oriented and may not fully characterize specific URLs/paths.
- VirusTotal adapter is optional and was not part of the original legacy integration.

## Security limitations / risks to address
- SSRF defenses are baseline (scheme/credential/private-IP literal checks, redaction) but need stronger redirect handling, DNS resolution/rebinding protections, and strict egress controls before high-trust deployment.
- `API_ACCESS_TOKEN` is optional by default for local dev; production exposure requires enforced auth, TLS, origin restrictions, and hardened rate limiting.
- Scanned URLs can contain sensitive data and may be transmitted to backend/providers; user guidance and minimization/redaction policies are required.
- Dependency and supply-chain security checks should be run regularly; pinned versions may need updates.

## Functional/product limitations
- Backend scan history is in-memory (non-persistent).
- Popup/extension and FastAPI behavior should be regression-tested end-to-end in both backend-online and backend-offline modes.
- Legacy Node and FastAPI response/latency semantics are similar but not exhaustively parity-tested across all provider edge cases.

## Future work
- Acquire/curate properly licensed datasets; train, calibrate, and version models reproducibly.
- Run full evaluation suite (heuristic vs ML vs reputation vs hybrid), ablations, robustness, and latency studies; publish actual tables/graphs.
- Add persistent storage, stronger authz/rate limiting, observability, and CI.
- Improve redirect-aware safe analysis, caching strategy, and provider adapters with comprehensive mocked/live contract tests.
- Finalize research report and diagrams with measured results and explicit methodology.
