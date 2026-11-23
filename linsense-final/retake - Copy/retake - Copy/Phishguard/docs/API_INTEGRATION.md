# API & Provider Integration

## FastAPI endpoints (`ai_backend/app/main.py`)

| Method | Path | Purpose | Notes |
|---|---|---|---|
| POST | `/scan` | Legacy-compatible scan for existing extension | Accepts `{ "url": "..." }`; returns consensus/risk/block/score/providers/errors plus AI extras (`risk_score`, `ml_probability`, `explanation`, `recommended_action`, `classification`, `confidence`, etc.). |
| POST | `/api/scan` | Structured hybrid scan | Returns `{ "result": ScanResult }` with heuristic, ML, reputation, fused verdict, explanation. |
| POST | `/api/explain` | Explain existing scan result | Generates explanation from provided structured result; **does not change verdict**. |
| GET | `/health` | Backend/model/provider config status | Reports ML availability and which provider keys are configured (no secrets). |
| GET | `/api/model/info` | Model metadata | Name/version, feature schema, training metadata (defaults when no trained artifact). |
| GET | `/api/scan/history` | Recent scan history (in-memory) | Requires auth only if `API_ACCESS_TOKEN` is set (same auth helper as scan/explain). |

## Request validation & security controls
- URL must be `http://` or `https://`; embedded credentials rejected.
- Direct private/reserved IP literals rejected (`app.security`); unparseable/missing host rejected.
- In-memory rate limiting per client IP for scan/explain; request size checks in middleware/handlers.
- Optional bearer auth via `API_ACCESS_TOKEN`.
- URL redaction in logs/explanations; providers must not be trusted as instruction sources.

## Reputation providers (adapters)

| Provider | Adapter | Typical input | Notes |
|---|---|---|---|
| urlscan.io | `providers/urlscan.py` | URL submission (private) + result poll | Key required; availability depends on API/scan completion. |
| AbuseIPDB | `providers/abuseipdb.py` | Resolved public IPv4(s) for hostname | Domain-wide coverage limited; no public IPv4 => unavailable. |
| AlienVault OTX | `providers/otx.py` | Domain indicator | Pulse/threat-tag based normalization. |
| Pulsedive | `providers/pulsedive.py` | Host/domain indicator | Risk string/score normalized to safe/suspicious/malicious. |
| MetaDefender Cloud | `providers/metadefender.py` | URL scan/report | Handles async report polling and result shapes. |
| VirusTotal | `providers/virustotal.py` | URL analysis | **Optional; not in original legacy backend.** Disabled/unkeyed => unavailable. |

## Normalization & aggregation semantics
- Each adapter returns `ProviderResult { name, available, verdict, score?, details, error?, pending }`.
- `available=false` or missing verdict => unavailable (never counted as safe).
- Aggregation (`app.reputation.aggregate_results`): majority consensus among available votes; ties break to more severe verdict; any available non-safe contributes to risk/block; score derived from suspicious/malicious vote counts.
- Fusion combines reputation with heuristic/ML; final classification is evidence-based and may differ from raw consensus.

## Legacy Node backend (`backend/server.js`)
- Preserved as-is for compatibility/testing: `POST /scan`, `GET /health`, 5-provider aggregation, in-memory cache/in-flight handling, partial/early-risk behavior. Uses server-side `.env` keys.

## Extension integration
- `background.js` posts to configured backend URL (default `http://127.0.0.1:8787/scan`) and merges response with local analysis; on failure/unavailable, falls back to local analysis.
- `popup/popup.js` renders provider results plus hybrid/AI fields when present.
