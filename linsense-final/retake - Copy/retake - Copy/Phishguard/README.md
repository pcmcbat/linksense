# LinkSense AI - Hybrid Phishing Detection System

A Chrome Manifest V3 browser extension powered by a FastAPI backend combining heuristic detection, machine learning classification, threat intelligence APIs, and AI-generated security explanations.

## Features

- **Local Heuristic Detection** - Instant offline URL analysis with suspicious indicator scoring
- **ML-Powered Classification** - Random Forest model trained on phishing/legitimate URL features
- **Threat Intelligence APIs** - 6 reputation providers (urlscan.io, AbuseIPDB, AlienVault OTX, Pulsedive, MetaDefender Cloud, VirusTotal)
- **Hybrid Risk Fusion** - Transparent evidence combination with calibrated confidence
- **AI Explanations** - LLM-powered security explanations with deterministic fallback
- **Real-Time Protection** - Automatic blocking with warning pages
- **Privacy-First** - API keys stored server-side only

## Project Structure

```
Phishguard/
  manifest.json          # Chrome Extension Manifest V3
  background.js          # Extension service worker
  content.js             # Page content analysis
  popup/                 # Extension popup UI
  backend/               # Legacy Node.js backend (5 providers)
  ai_backend/            # FastAPI hybrid backend (ML + AI)
    app/
      main.py            # FastAPI application
      config.py          # Settings (Pydantic)
      schemas.py         # API schemas
      features.py        # URL feature extraction
      heuristic.py       # Local heuristic scoring
      fusion.py          # Evidence fusion engine
      explain.py         # AI explanation generator
      reputation.py      # Provider aggregation
      security.py        # SSRF protection, URL validation
    ml/
      predict.py         # ML predictor interface
      train.py           # Model training pipeline
      model.joblib       # Trained model artifact
      model_meta.json    # Model metadata
    providers/           # 6 reputation provider adapters
    tests/               # 36 automated tests
```

## Quick Start

### 1. Run the FastAPI Backend

```powershell
cd ai_backend
Copy-Item .env.example .env
# Add your API keys to .env (server-side only)
uvicorn app.main:app --host 127.0.0.1 --port 8787
```

### 2. Load the Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select this repository folder
4. The extension defaults to `http://127.0.0.1:8787/scan` backend

### 3. Configure API Keys (Optional)

Copy `.env.example` to `.env` and add keys for:
- `URLSCAN_API_KEY` - urlscan.io
- `ABUSEIPDB_API_KEY` - AbuseIPDB
- `OTX_API_KEY` - AlienVault OTX
- `PULSEDIVE_API_KEY` - Pulsedive
- `METADEFENDER_API_KEY` - MetaDefender Cloud
- `VIRUSTOTAL_API_KEY` - VirusTotal (optional)
- `LLM_API_KEY` - For AI explanations (optional)

### 4. Train the ML Model (Optional)

```powershell
cd ai_backend
python ml/train.py --data ml/data/urls.csv
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Full hybrid scan (heuristic + ML + reputation + AI explanation) |
| `/scan` | POST | Legacy-compatible scan (Chrome extension integration) |
| `/api/explain` | POST | Generate explanation for existing scan result |
| `/health` | GET | Backend status, ML availability, provider config |
| `/api/model/info` | GET | Model name, version, feature schema |
| `/api/scan/history` | GET | Recent scan history |

### Example: Scan a URL

```bash
curl -X POST http://127.0.0.1:8787/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Response includes:
- `verdict`: safe | suspicious | malicious
- `risk_score`: 0-100
- `ml_probability`: phishing probability (calibrated)
- `heuristic_score`: local heuristic score
- `explanation`: human-readable security explanation
- `providers`: reputation provider results

## Testing

```powershell
cd ai_backend
python -m pytest tests/ -v
```

All 36 tests pass covering:
- Feature extraction
- ML prediction
- Risk fusion
- Reputation aggregation
- Security (SSRF protection, URL validation)
- API endpoints

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Chrome Extension                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Content.js │  │ Background  │  │   Popup     │         │
│  │ (Page scan) │  │  Service    │  │    UI       │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                 │                 │
└─────────┼────────────────┼─────────────────┼─────────────────┘
          │                │                 │
          └────────────────┼─────────────────┘
                           │
                    ┌──────▼──────┐
                    │  FastAPI    │
                    │  Backend    │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐       ┌────▼────┐       ┌────▼────┐
   │ Heuristic│       │   ML    │       │Reputation│
   │ Scoring  │       │ Predictor│      │ Providers│
   └─────────┘       └─────────┘       └─────────┘
```

## Security

- **SSRF Protection** - Private/reserved IP blocking, URL validation
- **API Keys Server-Side** - Never exposed to frontend
- **URL Redaction** - Credentials stripped from logs
- **Rate Limiting** - Per-IP request throttling
- **CORS Restrictions** - Configurable allowed origins
- **Request Size Limits** - 64KB max request body

## License

MIT License

## Acknowledgments

- urlscan.io, AbuseIPDB, AlienVault OTX, Pulsedive, MetaDefender Cloud, VirusTotal for reputation data
- Chrome Extensions Team for Manifest V3 documentation