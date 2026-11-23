"""Pulsedive provider adapter (ported from existing Node backend)."""

import logging

import httpx

from app.reputation import BaseProvider
from app.security import redact_url

logger = logging.getLogger("linksense.providers.pulsedive")


class PulsediveProvider(BaseProvider):
    def __init__(self, api_key: str, timeout: float = 10.0):
        super().__init__("Pulsedive", timeout)
        self.api_key = api_key

    async def check(self, url: str, hostname: str):
        if not self.api_key:
            return self.unavailable("API key is not configured")
        client = await self._get_client()
        try:
            params = {"indicator": hostname, "key": self.api_key}
            r = await client.get("https://pulsedive.com/api/indicator.php", params=params)
            if r.status_code >= 400:
                return self.unavailable(f"HTTP {r.status_code}")
            data = r.json()
            if data.get("error") or data.get("success") is False:
                return self.unavailable("Indicator lookup failed")
            risk_value = data.get("risk") or (data.get("indicator") or {}).get("risk")
            if risk_value is None:
                return self.unavailable("Pulsedive risk is unavailable")
            if isinstance(risk_value, (int, float)) or (isinstance(risk_value, str) and risk_value.strip().isdigit()):
                score = int(risk_value)
                verdict = "malicious" if score >= 75 else ("suspicious" if score >= 50 else "safe")
                return self.success(verdict, score=score, details={"risk": risk_value})
            risk = str(risk_value).lower().strip()
            verdict = "malicious" if risk in ("high", "critical") else (
                "suspicious" if risk in ("low", "medium") else (
                    "safe" if risk in ("none", "very low", "retired") else None
                )
            )
            if verdict is None:
                return self.unavailable("Pulsedive has no assessed risk for this indicator")
            score = {"malicious": 90, "suspicious": 55, "safe": 0}[verdict]
            return self.success(verdict, score=score, details={"risk": risk})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Pulsedive failed for %s: %s", redact_url(url), exc)
            return self.unavailable(f"Provider request failed: {exc}")
