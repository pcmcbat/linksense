"""AlienVault OTX provider adapter (ported from existing Node backend)."""

import logging

import httpx

from app.reputation import BaseProvider
from app.security import redact_url

logger = logging.getLogger("linksense.providers.otx")


class OTXProvider(BaseProvider):
    def __init__(self, api_key: str, timeout: float = 10.0):
        super().__init__("AlienVault OTX", timeout)
        self.api_key = api_key

    async def check(self, url: str, hostname: str):
        if not self.api_key:
            return self.unavailable("API key is not configured")
        client = await self._get_client()
        try:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/general",
                headers={"X-OTX-API-KEY": self.api_key},
            )
            if r.status_code >= 400:
                return self.unavailable(f"HTTP {r.status_code}")
            data = r.json()
            pulse_info = data.get("pulse_info", {}) or {}
            count = pulse_info.get("count")
            if not isinstance(count, (int, float)):
                return self.unavailable("Invalid OTX response")
            threat_terms = ("malware", "phishing", "malicious", "ransomware", "trojan",
                            "botnet", "command.and.control", "c2", "credential theft", "spyware")
            threat_pulses = 0
            for pulse in pulse_info.get("pulses", []) or []:
                text = f"{pulse.get('name','')} {' '.join(pulse.get('tags') or [])}".lower()
                if any(t in text for t in threat_terms):
                    threat_pulses += 1
            whitelisted = any(
                "whitelist" in str(p.get("name", "")).lower()
                or "whitelist" in str(p.get("message", "")).lower()
                for p in data.get("validation", []) or []
            )
            verdict = "suspicious" if threat_pulses > 0 and not whitelisted else "safe"
            return self.success(verdict, details={
                "pulse_count": count, "threat_pulse_count": threat_pulses, "whitelisted": whitelisted
            })
        except Exception as exc:  # noqa: BLE001
            logger.warning("AlienVault OTX failed for %s", redact_url(url))
            return self.unavailable(f"Provider request failed: {exc}")
