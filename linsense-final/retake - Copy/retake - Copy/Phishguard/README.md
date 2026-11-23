# LinkSense AI — Hybrid Phishing Detection System (Upgrade Workspace)

This repository contains the original **LinkSense** Chrome Manifest V3 extension and an in-progress upgrade toward **LinkSense AI**: a hybrid system combining existing heuristic detection, ML-based classification (when trained), threat-intelligence reputation checks, evidence fusion, and AI-generated explanations.

> **Status:** engineering scaffold and partial integration implemented. **No real training dataset, trained model artifacts, or fabricated performance metrics are included.** Live reputation/LLM results depend on user-provided, server-side API keys and external service availability. Existing local/legacy behavior must remain usable when the backend or AI services are unavailable.

## Repository layout (actual)

- `manifest.json`, `background.js`, `content.js`, `popup/`, `blocked.html`, `static/`, `rules.json` — existing Chrome extension (preserved baseline).
- `backend/` — legacy Node.js reputation backend (`POST /scan`, `GET /health`, 5 providers) and tests.
- `ai_backend/` — FastAPI hybrid backend scaffold (`/scan` legacy-compatible + `/api/scan`, `/api/explain`, `/health`, `/api/model/info`, `/api/scan/history`), ML pipeline stubs, provider adapters, fusion/explanation, and pytest suite.
- `docs/` — architecture, API, fusion, ML/evaluation, deployment, and limitations documentation (implemented vs pending clearly marked).

## What is implemented now

- **Extension (baseline preserved):** MV3 scanning flow, local heuristic analysis/scoring, dynamic blocking/warning UX, popup status/manual scan/history/trust controls, content-script page signals, configurable backend URL, fallback to local analysis when backend unavailable.
- **Legacy Node backend:** server-side aggregation for urlscan.io, AbuseIPDB, AlienVault OTX, Pulsedive, MetaDefender Cloud with unavailable≠safe handling.
- **FastAPI `ai_backend`:** URL validation/SSRF baseline checks, heuristic analysis, ML predictor interface (graceful when model unavailable), reputation aggregation layer, transparent fusion engine, deterministic/LLM-optional explanation (verdict not overridden), legacy-compatible `/scan` plus structured `/api/*` endpoints, in-memory history/rate limiting, and automated tests for core modules/contracts.
- **Popup AI surfacing:** displays hybrid risk/AI fields when provided by backend (risk score, explanation, recommended action, ML probability, heuristic score, model/confidence, provider results).

## What is NOT complete / externally blocked

- **Trained ML model & real metrics:** no `ai_backend/ml/model.joblib` or `model_meta.json` shipped; no real labeled dataset in repo. Training, calibration, thresholds-from-validation, comparative/ablation/robustness experiments, and graphs/tables **require legitimately sourced data and must be reported only from actual runs**.
- **Live provider/LLM verification:** requires valid API keys configured in backend `.env` (server-side only). VirusTotal is an optional adapter (not part of original legacy integration).
- **Full production hardening & parity:** additional provider-contract verification, redirect/DNS-rebind defenses, auth/CORS/rate-limit hardening, persistent storage, and broader e2e/regression automation are pending (see `docs/LIMITATIONS.md`).
- **Academic deliverables:** diagrams/docs/report scaffolding provided; experimental results must be filled from real experiments.

## Quick start

### 1) Legacy Node backend (existing providers, 5-service consensus)
```powershell
cd backend
Copy-Item .env.example .env
# add keys in .env (never commit secrets)
npm install  # if needed
npm start    # default 127.0.0.1:8787
```

### 2) FastAPI hybrid backend (`ai_backend`)
```powershell
cd ai_backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# add provider/LLM keys and optional API_ACCESS_TOKEN in .env
uvicorn app.main:app --host 127.0.0.1 --port 8787
```

### 3) Load extension
1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select this repository folder
4. In popup, set backend URL if needed (default `http://127.0.0.1:8787/scan`)

### 4) Tests
```powershell
# FastAPI backend
cd ai_backend
python -m pytest -q

# Legacy Node backend
cd backend
npm test
```

## Security & privacy notes
- Store all API keys/tokens server-side in `.env` files only; **never** put secrets in extension JS, popup, or committed files.
- Scanned URLs may be sent to configured backend/providers; avoid scanning URLs containing credentials/tokens/private query data.
- Backend rejects non-HTTP(S), embedded credentials, and direct private/reserved IP targets; do not auto-visit suspicious URLs.
- Unavailable providers/models must be treated as unavailable (never “safe”).

## Documentation
- `ai_backend/README.md` — backend setup/endpoints/training notes
- `docs/ARCHITECTURE.md` — current/hybrid architecture & data flow
- `docs/API_INTEGRATION.md` — endpoint/provider contracts
- `docs/RISK_FUSION.md` — feature/fusion math and thresholds
- `docs/ML_PIPELINE.md` — dataset/training/evaluation procedure (no fabricated results)
- `docs/DEPLOYMENT.md` — local/dev/deployment guidance
- `docs/LIMITATIONS.md` — known gaps, risks, and future work

## License
No `LICENSE` file detected in this workspace snapshot; verify and add the intended license before distribution.