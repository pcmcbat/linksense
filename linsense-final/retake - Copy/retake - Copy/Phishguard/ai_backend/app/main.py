"""LinkSense AI - FastAPI backend.

Endpoints:
  POST /api/scan          - full hybrid scan (new spec)
  POST /scan              - legacy alias matching the existing extension schema
  POST /api/explain       - explain an existing scan result (verdict unchanged)
  GET  /health            - backend + model + provider availability
  GET  /api/model/info    - model name/version/feature schema/training metadata
  GET  /api/scan/history  - in-memory scan history

Security:
  - URL validation + SSRF protection (app.security)
  - Request size limit
  - Restricted CORS
  - Optional API access token (API_ACCESS_TOKEN)
  - URL redaction in logs
  - Provider timeouts + retries handled per-adapter
"""

import asyncio
import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.explain import build_scan_result, generate_explanation
from app.fusion import fuse
from app.heuristic import analyze_url_locally
from app.reputation import aggregate_results
from ml.predict import MLPredictor
from providers.abuseipdb import AbuseIPDBProvider
from providers.metadefender import MetaDefenderProvider
from providers.otx import OTXProvider
from providers.pulsedive import PulsediveProvider
from providers.urlscan import UrlscanProvider
from providers.virustotal import VirusTotalProvider
from app.schemas import (
    ExplainRequest,
    ExplainResponse,
    HealthResponse,
    HeuristicResult,
    HistoryEntry,
    HistoryResponse,
    MLResult,
    ModelInfoResponse,
    ProviderResult,
    ReputationSummary,
    ScanRequest,
    ScanResponse,
)
from app.security import is_private_or_resolved_private, redact_url, validate_url_for_backend

logger = logging.getLogger("linksense.ai")

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await asyncio.gather(*(p.close() for p in PROVIDERS), return_exceptions=True)


app = FastAPI(
    title="LinkSense AI",
    description="Hybrid ML + Threat Intelligence phishing detection backend",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

predictor = MLPredictor(model_path=settings.model_path, meta_path=settings.model_meta_path)
_history: Deque = deque(maxlen=500)
_rate_limits: Dict[str, Deque[float]] = {}
RATE_LIMIT_MAX = 30
RATE_LIMIT_WINDOW = 60.0


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _rate_limited(request: Request) -> bool:
    now = time.time()
    ip = _client_ip(request)
    window = _rate_limits.setdefault(ip, deque())
    while window and window[0] < now - RATE_LIMIT_WINDOW:
        window.popleft()
    if len(window) >= RATE_LIMIT_MAX:
        return True
    window.append(now)
    return False


def _require_auth(request: Request) -> None:
    if not settings.api_access_token:
        return
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    if auth[7:].strip() != settings.api_access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")


@app.middleware("http")
async def request_size_and_logging(request: Request, call_next):
    # Request size limit via Content-Length header (~64 KB)
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > 65536:
                return JSONResponse(status_code=413, content={"error": "Request too large"})
        except ValueError:
            pass
    logger.info("request %s %s", request.method, redact_url(str(request.url)))
    response = await call_next(request)
    return response


def build_providers() -> list:
    return [
        UrlscanProvider(settings.urlscan_api_key, settings.provider_timeout),
        AbuseIPDBProvider(settings.abuseipdb_api_key, settings.provider_timeout),
        OTXProvider(settings.otx_api_key, settings.provider_timeout),
        PulsediveProvider(settings.pulsedive_api_key, settings.provider_timeout),
        MetaDefenderProvider(settings.metadefender_api_key, settings.provider_timeout),
        VirusTotalProvider(settings.virustotal_api_key, settings.provider_timeout),
    ]


PROVIDERS = build_providers()
@app.get("/health", response_model=HealthResponse)
async def health():
    provider_configured = {
        "urlscan": bool(settings.urlscan_api_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "otx": bool(settings.otx_api_key),
        "pulsedive": bool(settings.pulsedive_api_key),
        "metadefender": bool(settings.metadefender_api_key),
        "virustotal": bool(settings.virustotal_api_key),
    }
    status_val = "ok" if predictor.is_available() else "degraded"
    return HealthResponse(
        status=status_val,
        ml_available=predictor.is_available(),
        model_version=predictor.model_info().get("model_version"),
        providers=provider_configured,
    )
@app.get("/api/model/info", response_model=ModelInfoResponse)
async def model_info():
    info = predictor.model_info()
    return ModelInfoResponse(
        model_name=info.get("model_name", "RandomForestClassifier"),
        model_version=info.get("model_version"),
        feature_schema=info.get("feature_schema", []),
        training_metadata=info.get("training_metadata", {}),
    )


@app.get("/api/scan/history", response_model=HistoryResponse)
async def scan_history(request: Request):
    _require_auth(request)
    entries = [HistoryEntry(**h) for h in list(_history)]
    return HistoryResponse(history=entries)


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------

async def _run_reputation(url: str, hostname: str):
    results = await asyncio.gather(
        *(p.check(url, hostname) for p in PROVIDERS), return_exceptions=True
    )
    normalized = []
    for p, res in zip(PROVIDERS, results):
        if isinstance(res, Exception):
            normalized.append(p.unavailable(f"Provider error: {res}"))
        else:
            normalized.append(res)
    return aggregate_results(normalized)


def _legacy_scan_schema(result, reputation_summary: dict) -> dict:
    """Schema the existing Node extension expects from /scan."""
    if hasattr(result, "model_dump"):
        verdict = result.verdict
        risk_score = result.risk_score
        heuristic_signals = list(result.heuristic.signals or [])
        errors = list(result.errors or [])
        source = result.source or "hybrid"
        ml_probability = result.ml_probability
        ml = result.ml.model_dump() if hasattr(result.ml, "model_dump") else result.ml
        explanation = result.explanation
        classification = result.classification
        confidence = result.confidence
        checked_at = result.checked_at
        recommended_action = getattr(result, "recommended_action", "")
        provider_availability = getattr(result, "provider_availability", {})
    else:
        verdict = result["verdict"]
        risk_score = result["risk_score"]
        heuristic_signals = result.get("heuristic_signals", []) or (result.get("heuristic") or {}).get("signals", [])
        errors = result.get("errors", [])
        source = result.get("source", "hybrid")
        ml_probability = result.get("ml_probability")
        ml = result.get("ml")
        explanation = result.get("explanation")
        classification = result.get("classification")
        confidence = result.get("confidence")
        checked_at = result.get("checked_at")
        recommended_action = result.get("recommended_action", "")
        provider_availability = result.get("provider_availability", {})

    providers = reputation_summary.get("providers", [])
    provider_list = []
    for pr in providers:
        if hasattr(pr, "model_dump"):
            provider_list.append({
                "name": pr.name,
                "available": pr.available,
                "verdict": pr.verdict,
                "error": pr.error,
                "pending": pr.pending,
            })
        else:
            provider_list.append({
                "name": pr.get("name"),
                "available": pr.get("available"),
                "verdict": pr.get("verdict"),
                "error": pr.get("error"),
                "pending": pr.get("pending", False),
            })
    return {
        "verdict": verdict,
        "consensusVerdict": reputation_summary.get("consensus_verdict") or verdict,
        "riskVerdict": reputation_summary.get("risk_verdict") or verdict,
        "block": verdict in ("suspicious", "malicious"),
        "score": risk_score,
        "signals": heuristic_signals,
        "errors": errors,
        "providers": provider_list,
        "consensus": reputation_summary.get("consensus"),
        "partial": reputation_summary.get("partial", False),
        "unavailable": reputation_summary.get("unavailable", False),
        "source": source,
        # New AI fields (extras, ignored by legacy client)
        "risk_score": risk_score,
        "ml_probability": ml_probability,
        "ml": ml,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "classification": classification,
        "confidence": confidence,
        "provider_availability": provider_availability,
        "checked_at": checked_at.isoformat() if hasattr(checked_at, "isoformat") else checked_at,
    }


# ---------------------------------------------------------------------------
# POST /api/scan (new spec) + POST /scan (legacy alias)
# ---------------------------------------------------------------------------

@app.post("/api/scan", response_model=ScanResponse)
async def api_scan(request: Request, payload: ScanRequest):
    _require_auth(request)
    if _rate_limited(request):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return await _perform_scan(request, payload.url, legacy=False)


@app.post("/scan")
async def legacy_scan(request: Request, payload: ScanRequest):
    _require_auth(request)
    if _rate_limited(request):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    out = await _perform_scan(request, payload.url, legacy=True)
    return JSONResponse(content=_legacy_scan_schema(out["result"], out["reputation_summary"]))


async def _perform_scan(request: Request, url: str, legacy: bool = False):
    from urllib.parse import urlparse

    url = url.strip()
    ok, reason = validate_url_for_backend(url)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    hostname = urlparse(url).hostname or ""
    if is_private_or_resolved_private(hostname):
        raise HTTPException(status_code=400, detail="Private or reserved IP addresses are not allowed")

    # 1. Heuristic (existing baseline, preserved)
    heuristic_dict = analyze_url_locally(url)
    heuristic = HeuristicResult(
        verdict=heuristic_dict["verdict"],
        score=heuristic_dict["score"],
        signals=heuristic_dict.get("signals", []),
        source=heuristic_dict.get("source", "local"),
    )

    # 2. ML prediction
    ml_pred = predictor.predict(url)
    ml = MLResult(
        prediction=ml_pred["prediction"],
        probability=ml_pred["probability"],
        model_version=ml_pred.get("model_version"),
        top_features=ml_pred.get("top_features", []),
        available=ml_pred.get("available", False),
        error=ml_pred.get("error"),
    )

    # 3. Reputation providers (parallel)
    reputation_summary = await _run_reputation(url, hostname)
    providers = reputation_summary["providers"]
    if not isinstance(providers, list):
        providers = []
    reputation = ReputationSummary(
        verdict=reputation_summary["verdict"],
        consensus_verdict=reputation_summary.get("consensus_verdict"),
        risk_verdict=reputation_summary.get("risk_verdict"),
        block=reputation_summary["block"],
        score=reputation_summary["score"],
        providers=[ProviderResult(**p) if isinstance(p, dict) else p for p in providers],
        consensus=reputation_summary.get("consensus"),
        errors=list(reputation_summary.get("errors", [])),
        source=reputation_summary.get("source"),
        partial=bool(reputation_summary.get("partial", False)),
        unavailable=bool(reputation_summary.get("unavailable", False)),
    )

    # 4. Fuse evidence
    fused = fuse(heuristic=heuristic, ml=ml, reputation=reputation)

    # 5. Explanation (verdict never overridden)
    explanation_resp = await generate_explanation(
        url, heuristic, ml, reputation, fused, original_verdict=fused["verdict"]
    )

    # 6. Build scan result
    scan_result = build_scan_result(
        url, heuristic, ml, reputation, fused, explanation_resp.explanation,
        source="legacy-scan" if legacy else "hybrid",
    )

    # 7. Store in history
    _history.appendleft({
        "url": scan_result.url,
        "verdict": scan_result.verdict,
        "risk_score": scan_result.risk_score,
        "classification": scan_result.classification,
        "checked_at": scan_result.checked_at.isoformat(),
    })

    return {"result": scan_result, "reputation_summary": reputation_summary}


# ---------------------------------------------------------------------------
# POST /api/explain
# ---------------------------------------------------------------------------

@app.post("/api/explain", response_model=ExplainResponse)
async def api_explain(request: Request, payload: ExplainRequest):
    _require_auth(request)
    if _rate_limited(request):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    sr = payload.scan_result
    heuristic = HeuristicResult(
        verdict=sr.heuristic.verdict,
        score=sr.heuristic.score,
        signals=sr.heuristic.signals,
        source=sr.heuristic.source,
    )
    ml = MLResult(
        prediction=sr.ml.prediction,
        probability=sr.ml.probability,
        model_version=sr.ml.model_version,
        top_features=sr.ml.top_features,
        available=sr.ml.available,
        error=sr.ml.error,
    )
    providers = [ProviderResult(**p) if isinstance(p, dict) else p for p in (sr.reputation.providers or [])]
    reputation = ReputationSummary(
        verdict=sr.reputation.verdict,
        consensus_verdict=sr.reputation.consensus_verdict,
        risk_verdict=sr.reputation.risk_verdict,
        block=sr.reputation.block,
        score=sr.reputation.score,
        providers=providers,
        consensus=sr.reputation.consensus,
        errors=list(sr.reputation.errors or []),
        source=sr.reputation.source,
        partial=bool(sr.reputation.partial),
        unavailable=bool(sr.reputation.unavailable),
    )
    fused = fuse(heuristic=heuristic, ml=ml, reputation=reputation)
    return await generate_explanation(
        sr.url, heuristic, ml, reputation, fused, original_verdict=sr.verdict
    )


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(400)
async def bad_request(request: Request, exc):
    return JSONResponse(status_code=400, content={"error": "Bad request", "detail": str(exc)})


@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"error": "Not found"})


@app.exception_handler(413)
async def too_large(request: Request, exc):
    return JSONResponse(status_code=413, content={"error": "Request too large"})


@app.exception_handler(429)
async def rate_limited(request: Request, exc):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})


@app.exception_handler(500)
async def server_error(request: Request, exc):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.get("/")
async def root():
    return {"service": "LinkSense AI", "version": "1.0.0", "status": "running"}


