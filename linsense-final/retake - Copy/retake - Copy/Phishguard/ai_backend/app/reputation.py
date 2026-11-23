"""Reputation intelligence: provider adapters and evidence aggregation.

Each provider is an independent adapter that handles authentication, URL/domain
lookup, response normalization, timeout handling, rate-limit handling, provider
errors, unavailable status, and retry policies. An unavailable provider is never
treated as a clean (safe) result.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.schemas import ProviderResult
from app.security import redact_url

logger = logging.getLogger("linksense.reputation")

PROVIDER_NAMES = ["urlscan.io", "AbuseIPDB", "AlienVault OTX", "Pulsedive",
                  "MetaDefender Cloud", "VirusTotal"]

SEVERITY = {"safe": 0, "suspicious": 1, "malicious": 2}


class BaseProvider(ABC):
    def __init__(self, name: str, timeout: float = 10.0):
        self.name = name
        self.timeout = timeout
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self._http_client

    async def close(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    @abstractmethod
    async def check(self, url: str, hostname: str) -> ProviderResult:
        """Look up reputation for the URL/hostname. Never treat unavailable as safe."""

    def unavailable(self, error: str, pending: bool = False) -> ProviderResult:
        return ProviderResult(name=self.name, available=False, verdict=None,
                              error=error, pending=pending)

    def success(self, verdict: str, score: Optional[int] = None,
                details: Optional[Dict[str, Any]] = None) -> ProviderResult:
        return ProviderResult(name=self.name, available=True, verdict=verdict,
                              score=score, details=details or {})


def classify_severity(verdicts: List[str]) -> str:
    """Return the most severe verdict among a list."""
    highest = "safe"
    for v in verdicts:
        if SEVERITY.get(v, 0) > SEVERITY.get(highest, 0):
            highest = v
    return highest


def aggregate_results(results: List[ProviderResult]) -> Dict[str, Any]:
    """Aggregate provider results into a reputation summary.

    Ported from the existing LinkSense Node backend semantics:
      - Majority verdict among available providers.
      - Ties broken toward the more severe verdict.
      - Any available non-safe provider => block.
      - Unavailable providers are never counted as safe.
      - If no provider returns a verdict => unavailable.
    """
    votes = [r for r in results if r.available and r.verdict in SEVERITY]
    errors = [f"{r.name}: {r.error}" for r in results if not r.available and r.error]
    pending = any(r.pending for r in results if not r.available)

    if not votes:
        return {
            "verdict": "unavailable",
            "consensus_verdict": None,
            "risk_verdict": None,
            "block": False,
            "score": 0,
            "providers": results,
            "consensus": {"votes": {"safe": 0, "suspicious": 0, "malicious": 0},
                          "available": 0, "total": len(results)},
            "errors": errors,
            "source": "reputation providers (0 available)",
            "partial": pending,
            "unavailable": True,
        }

    counts = {"safe": 0, "suspicious": 0, "malicious": 0}
    for r in votes:
        counts[r.verdict] += 1

    # Majority; ties -> more severe.
    consensus = max(counts.items(), key=lambda kv: (kv[1], SEVERITY[kv[0]]))[0]
    risk = classify_severity([r.verdict for r in votes])
    blocked = any(r.verdict != "safe" for r in votes)
    score = round((counts["suspicious"] * 60 + counts["malicious"] * 100) /
                  max(len(votes), 1))

    return {
        "verdict": consensus,
        "consensus_verdict": consensus,
        "risk_verdict": risk,
        "block": blocked,
        "score": score,
        "providers": results,
        "consensus": {"votes": counts, "available": len(votes), "total": len(results)},
        "errors": errors,
        "source": f"reputation consensus ({len(votes)}/{len(results)} available)",
        "partial": pending,
        "unavailable": False,
    }
