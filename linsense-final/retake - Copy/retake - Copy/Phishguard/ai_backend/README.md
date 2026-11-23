# LinkSense AI Backend (FastAPI)

Hybrid backend scaffold for LinkSense AI: heuristic analysis, ML prediction (when model artifacts are provided), reputation-provider aggregation, evidence fusion, and explanation generation.

**Status:** in-progress upgrade. Preserves compatibility with the existing extension's legacy `/scan` contract and adds `/api/scan` + related endpoints. ML results are unavailable until a trained model is supplied (`ml/model.joblib` + `ml/model_meta.json`). Reputation providers require server-side API keys; unavailable providers are never treated as safe.

## Requirements
- Python 3.10+ (tested in repo environment with 3.13)
- Dependencies: `ai_backend/requirements.txt`

## Setup
```powershell
cd ai_backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env with provider keys/tokens as needed (never commit .env)
```

## Run
```powershell
cd ai_backend
uvicorn app.main:app --host 127.0.0.1 --port 8787
```
Default bind matches the extension's default backend URL (`http://127.0.0.1:8787/scan`). For deployment, use HTTPS and set `API_ACCESS_TOKEN`.

## Endpoints
- `POST /scan` — legacy-compatible response for existing extension
- `POST /api/scan` — structured hybrid scan result
- `POST /api/explain` — explain existing scan result (does not change verdict)
- `GET /health` — backend/model/provider configuration status
- `GET /api/model/info` — model name/version/feature schema/metadata
- `GET /api/scan/history` — in-memory scan history

## Tests
```powershell
cd ai_backend
python -m pytest -q
```

## Security notes
- Keep all API keys and tokens in `.env` (server-side only). Never expose secrets in extension/frontend code.
- Backend validates URL scheme/shape and rejects embedded credentials and direct private/reserved IP targets (SSRF mitigation baseline).
- Do not auto-visit user-supplied suspicious URLs.
- Optional bearer auth: set `API_ACCESS_TOKEN` and send `Authorization: Bearer <token>`.

## ML training (when you provide a dataset)
No dataset or model artifacts are included. See `data/README.md` for required format, sourcing/licensing, and preprocessing expectations.
```powershell
cd ai_backend
python -m ml.train --data data/urls.csv --model-out ml/model.joblib --meta-out ml/model_meta.json
```
Do not fabricate datasets or performance metrics; evaluate and document results only from real experiments.
