"""VirusTotal provider adapter (OPTIONAL).

VirusTotal is NOT part of the original LinkSense repository's implemented backends.
It is included here as a clearly-marked optional provider. Enable it only when a
VIRUSTOTAL_API_KEY is configured; otherwise it reports as unavailable (never safe).
"""

import asyncio
import logging

import httpx

from app.reputation import BaseProvider
from app.security import redact_url

logger = logging.getLogger("linksense.providers.virustotal")


class VirusTotalProvider(BaseProvider):
    def __init__(self, api_key: str, timeout: float = 10.0):
        super().__init__("VirusTotal", timeout)
        self.api_key = api_key

    async def check(self, url: str, hostname: str):
        if not self.api_key:
            return self.unavailable("API key is not configured")
        client = await self._get_client()
        try:
            # VirusTotal URL analysis: submit URL for scanning
            r = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": self.api_key},
                data={"url": url},
            )
            if r.status_code >= 400:
                return self.unavailable(f"HTTP {r.status_code}")
            data = r.json()
            analysis_id = data.get("data", {}).get("id")
            if not analysis_id:
                return self.unavailable("Missing analysis identifier")
            # Poll for result
            for _ in range(5):
                await asyncio.sleep(2)
                rr = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": self.api_key},
                )
                if rr.status_code >= 400:
                    return self.unavailable(f"HTTP {rr.status_code}")
                res = rr.json()
                status = res.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    stats = res.get("data", {}).get("attributes", {}).get("stats", {})
                    malicious = int(stats.get("malicious", 0))
                    suspicious = int(stats.get("suspicious", 0))
                    verdict = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "safe")
                    return self.success(verdict, score=malicious + suspicious,
                                        details={"malicious": malicious, "suspicious": suspicious})
            return self.unavailable("VirusTotal analysis not ready")
        except Exception as exc:  # noqa: BLE001
            logger.warning("VirusTotal failed for %s: %s", redact_url(url), exc)
            return self.unavailable(f"Provider request failed: {exc}")
