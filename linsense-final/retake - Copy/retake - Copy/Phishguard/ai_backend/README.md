# LinkSense AI - FastAPI Backend

Hybrid phishing detection backend combining heuristic analysis, machine learning classification, threat intelligence APIs, and AI-generated explanations.

## Setup

```powershell
# Install dependencies
pip install -r requirements.txt

# Configure environment
Copy-Item .env.example .env
# Edit .env to add your API keys

# Run the server
uvicorn app.main:app --host 127.0.0.1 --port 8787
```

## API Endpoints

### POST /api/scan

Full hybrid scan with all detection layers.

**Request:**
```json
{"url": "https://example.com"}
```

**Response:**
```json
{
  "result": {
    "url": "https://example.com",
    "verdict": "safe",
    "risk_score": 2,
    "ml_probability": 0.0295,
    "heuristic_score": 0,
    "classification": "Safe",
    "ml": {
      "prediction": "safe",
      "probability": 0.0295,
      "model_version": "linksense-ml-v1",
      "available": true
    },
    "heuristic": {
      "verdict": "safe",
      "score": 0,
      "signals": []
    },
    "reputation": {
      "verdict": "safe",
      "providers": [...]
    },
    "explanation": "LinkSense AI assessed https://example.com...",
    "recommended_action": "No specific action required.",
    "confidence": "high"
  }
}
```

### POST /scan (Legacy)

Legacy-compatible endpoint for Chrome extension integration. Returns the same structure as the Node.js backend with additional AI fields.

### POST /api/explain

Generate an AI explanation for an existing scan result (does not re-scan).

**Request:**
```json
{
  "scan_result": { /* full scan result from /api/scan */ }
}
```

### GET /health

Check backend status, ML model availability, and provider configuration.

**Response:**
```json
{
  "status": "ok",
  "ml_available": true,
  "model_version": "linksense-ml-v1",
  "providers": {
    "urlscan": true,
    "abuseipdb": true,
    "otx": true,
    "pulsedive": true,
    "metadefender": true,
    "virustotal": true
  }
}
```

### GET /api/model/info

Get model metadata.

**Response:**
```json
{
  "model_name": "RandomForestClassifier",
  "model_version": "linksense-ml-v1",
  "feature_schema": ["url_length", "domain_length", ...],
  "training_metadata": {}
}
```

### GET /api/scan/history

Get recent scan history (in-memory, max 500 entries).

## ML Model Training

Train a new model with labeled data:

```powershell
python ml/train.py --data ml/data/urls.csv --model-out ml/model.joblib --meta-out ml/model_meta.json
```

The training script:
1. Loads labeled URLs (url,label columns)
2. Extracts 20 features per URL
3. Trains and compares RandomForest, LogisticRegression, GradientBoosting
4. Calibrates the best model using isotonic regression
5. Saves model.joblib and model_meta.json

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| HOST | Server host | 127.0.0.1 |
| PORT | Server port | 8787 |
| URLSCAN_API_KEY | urlscan.io API key | - |
| ABUSEIPDB_API_KEY | AbuseIPDB API key | - |
| OTX_API_KEY | AlienVault OTX API key | - |
| PULSEDIVE_API_KEY | Pulsedive API key | - |
| METADEFENDER_API_KEY | MetaDefender Cloud API key | - |
| VIRUSTOTAL_API_KEY | VirusTotal API key (optional) | - |
| LLM_PROVIDER | LLM provider (none/openai/local) | none |
| LLM_API_KEY | LLM API key | - |
| API_ACCESS_TOKEN | Bearer token for API auth (production) | - |

## Running Tests

```powershell
python -m pytest tests/ -v
```

## Architecture

- **Heuristic**: Local URL pattern analysis (preserved from original LinkSense)
- **ML**: Random Forest with calibrated probabilities
- **Reputation**: 6 provider adapters with graceful degradation
- **Fusion**: Correlated (heuristic+ML) + independent (reputation) layers
- **Explanation**: LLM with deterministic fallback

See `../docs/` for detailed documentation.