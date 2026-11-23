"""Pydantic request/response schemas for the LinkSense AI API."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator


class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan")

    @field_validator("url")
    @classmethod
    def url_must_be_http_or_https(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL is required")
        v = v.strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("Only HTTP or HTTPS URLs are supported")
        return v


class ProviderResult(BaseModel):
    name: str
    available: bool
    verdict: Optional[str] = None  # safe | suspicious | malicious | None
    score: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    pending: bool = False


class ReputationSummary(BaseModel):
    verdict: str  # safe | suspicious | malicious | unavailable
    consensus_verdict: Optional[str] = None
    risk_verdict: Optional[str] = None
    block: bool = False
    score: int = 0
    providers: List[ProviderResult] = Field(default_factory=list)
    consensus: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)
    source: Optional[str] = None
    partial: bool = False
    unavailable: bool = False


class MLResult(BaseModel):
    model_config = {"protected_namespaces": ()}
    prediction: str  # safe | suspicious | malicious
    probability: float = Field(ge=0.0, le=1.0, description="Calibrated phishing probability")
    model_version: Optional[str] = None
    top_features: List[Dict[str, Any]] = Field(default_factory=list)
    available: bool = False
    error: Optional[str] = None


class HeuristicResult(BaseModel):
    verdict: str  # safe | suspicious | malicious
    score: int = Field(ge=0, le=100)
    signals: List[str] = Field(default_factory=list)
    source: str = "local"


class ScanResult(BaseModel):
    model_config = {"protected_namespaces": ()}
    url: str
    verdict: str  # safe | suspicious | malicious
    risk_score: int = Field(ge=0, le=100, description="Final hybrid risk score 0-100")
    ml_probability: float = Field(ge=0.0, le=1.0)
    heuristic_score: int = Field(ge=0, le=100)
    classification: str  # Safe | Suspicious | Malicious
    ml: MLResult
    heuristic: HeuristicResult
    reputation: ReputationSummary
    explanation: str
    recommended_action: str = ""
    confidence: str  # high | medium | low
    model_version: Optional[str] = None
    provider_availability: Dict[str, bool] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    source: str
    checked_at: datetime


class ScanResponse(BaseModel):
    result: ScanResult


class ExplainRequest(BaseModel):
    scan_result: ScanResult


class ExplainResponse(BaseModel):
    explanation: str
    verdict: str
    note: str = "Explanation does not override the original verdict."


class HealthResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    status: str  # ok | degraded
    ml_available: bool
    model_version: Optional[str] = None
    providers: Dict[str, bool]  # provider_name -> configured (key present)
    backend_version: str = "linksense-ai-1.0.0"


class ModelInfoResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_name: str
    model_version: Optional[str]
    feature_schema: List[str]
    training_metadata: Dict[str, Any] = Field(default_factory=dict)


class HistoryEntry(BaseModel):
    url: str
    verdict: str
    risk_score: int
    classification: str
    checked_at: datetime


class HistoryResponse(BaseModel):
    history: List[HistoryEntry]


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
