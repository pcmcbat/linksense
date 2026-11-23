# Architecture (Current + Hybrid Target)

## 1. Current baseline (preserved)

```mermaid
flowchart LR
  U[User / Browser Tab] --> CS[content.js]
  U --> POP[popup/popup.html + popup.js]
  POP <--> BG[background.js MV3 Service Worker]
  CS -->|PAGE_SIGNALS| BG
  BG -->|local heuristic + history/badge/blocking| STORE[(chrome.storage.local)]
  BG -->|DNR dynamic rules| DNR[declarativeNetRequest]
  BG -->|POST /scan {url}| NB[backend/server.js (Node, legacy)]
  NB --> P1[urlscan.io]
  NB --> P2[AbuseIPDB]
  NB --> P3[AlienVault OTX]
  NB --> P4[Pulsedive]
  NB --> P5[MetaDefender Cloud]
  BG --> BLK[blocked.html warning flow]
```

**Baseline behavior to preserve:** local scan works without backend; unavailable providers are not treated as safe; whitelist/pause/history/manual scan/threat decisions remain functional.

## 2. Hybrid FastAPI path (`ai_backend/`, in-progress)

```mermaid
flowchart LR
  POP2[Popup / Extension] -->|POST /scan or /api/scan| API[FastAPI app.main]
  API --> SEC[Validation + SSRF baseline\napp.security]
  API --> HEU[Heuristic baseline\napp.heuristic]
  API --> ML[ML predictor\nml.predict (model optional)]
  API --> REP[Reputation aggregation\napp.reputation]
  REP --> AD1[providers/urlscan]
  REP --> AD2[providers/abuseipdb]
  REP --> AD3[providers/otx]
  REP --> AD4[providers/pulsedive]
  REP --> AD5[providers/metadefender]
  REP --> AD6[providers/virustotal (optional)]
  HEU --> FUSE[Fusion engine\napp.fusion]
  ML --> FUSE
  REP --> FUSE
  FUSE --> EXP[Explanation\napp.explain\nLLM optional + deterministic fallback]
  EXP --> RES[Structured scan result\nlegacy-compatible fields + AI fields]
  RES --> POP2
```

## 3. Data flow (scan request)

1. **Input:** URL from extension/background/manual scan.
2. **Validate:** scheme/shape, reject embedded credentials and direct private/reserved IPs; redact for logs.
3. **Heuristic:** compute baseline score/verdict/signals (compatible with existing logic).
4. **ML (optional):** extract features (`app.features`) and predict calibrated phishing probability if model artifacts available; else return unavailable (not safe).
5. **Reputation:** query configured provider adapters in parallel, normalize outcomes, aggregate consensus/risk; unavailable != safe.
6. **Fusion:** combine correlated local evidence (heuristic, ML) with independent reputation evidence into 0–100 risk score + classification/confidence.
7. **Explain:** generate evidence-grounded explanation and recommended action; **explanation never overrides verdict**. Deterministic fallback when LLM unavailable.
8. **Persist (in-memory):** append to backend history; extension stores its own local history/state.
9. **Respond:** `/scan` returns legacy-compatible JSON + AI extras; `/api/scan` returns structured result.

## 4. Key implementation files
- Extension: `background.js`, `popup/*`, `content.js`, `blocked.html`, `manifest.json`
- Legacy backend: `backend/server.js`
- Hybrid backend: `ai_backend/app/{main,security,heuristic,features,fusion,reputation,explain,schemas,config}.py`, `ai_backend/providers/*`, `ai_backend/ml/{predict,train,evaluate}.py`
- Tests: `backend/server.test.js`, `ai_backend/tests/*`

## 5. Gaps
- Real trained model artifacts, dataset-backed validation, and live provider/LLM verification are environment/data/key dependent.
- See `docs/LIMITATIONS.md` for security hardening, persistence, and evaluation gaps.
