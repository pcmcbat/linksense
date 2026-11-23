# Deployment & Operations

## Local development

### Prerequisites
- Google Chrome (or Chromium-based browser supporting MV3)
- Python 3.10+ for `ai_backend`
- Node.js 18+ for legacy `backend` (optional compatibility path)

### Option A: FastAPI hybrid backend
```powershell
cd ai_backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# configure keys/tokens in .env
uvicorn app.main:app --host 127.0.0.1 --port 8787
```
Health check: `GET http://127.0.0.1:8787/health`

### Option B: Legacy Node backend
```powershell
cd backend
Copy-Item .env.example .env
npm install
npm start
```

### Load extension
1. `chrome://extensions` → Developer mode → Load unpacked → repo root.
2. Popup → set backend URL to the running endpoint (default `http://127.0.0.1:8787/scan`).

## Configuration
- `ai_backend/.env`: provider keys, optional LLM settings, `API_ACCESS_TOKEN`, timeouts, model paths, CORS/origins/host/port.
- `backend/.env`: legacy provider keys and host/port.
- **Never commit `.env` files or real secrets.** `.env.example` files contain placeholders only.

## Docker (FastAPI backend)
```powershell
cd ai_backend
docker build -t linksense-ai-backend .
docker run --rm -p 8787:8787 --env-file .env linksense-ai-backend
```
Mount/provide `ml/model.joblib` and `ml/model_meta.json` if using a trained model.

## HTTPS / production guidance
- Run behind TLS termination/reverse proxy (HTTPS).
- Set strong `API_ACCESS_TOKEN`; require bearer auth for non-local deployments.
- Restrict CORS/origins and network exposure; bind to intended interfaces only.
- Apply rate limiting/WAF controls appropriate to exposure; monitor logs and provider/API quotas.
- Do not log raw secrets or sensitive URL parameters; keep URL redaction enabled.

## Monitoring & maintenance
- Use `/health` and `/api/model/info` for readiness/diagnostics (no secret leakage).
- Track provider error rates, latency, timeout/unavailable ratios, and scan throughput.
- Re-train/recalibrate ML models only on documented, licensed datasets; version artifacts and metadata.

## Fallback behavior
- Extension must remain usable if backend/AI/providers are unavailable (local heuristic path preserved). Validate this after changes.
