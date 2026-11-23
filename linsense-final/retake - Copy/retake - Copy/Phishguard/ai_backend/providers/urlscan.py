"""urlscan.io provider adapter (ported from existing Node backend)."""

import asyncio
import logging

import httpx

from app.reputation import BaseProvider
from app.security import redact_url

logger = logging.getLogger("linksense.providers.urlscan")


class UrlscanProvider(BaseProvider):
    def __init__(self, api_key: str, timeout: float = 10.0):
        super().__init__("urlscan.io", timeout)
        self.api_key = api_key

    async def check(self, url: str, hostname: str):
        if not self.api_key:
            return self.unavailable("API key is not configured")
        client = await self._get_client()
        try:
            resp = await client.post(
                "https://urlscan.io/api/v1/scan",
                headers={"API-Key": self.api_key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "private"},
            )
            if resp.status_code >= 400:
                return self.unavailable(f"HTTP {resp.status_code}")
            data = resp.json()
            uuid = data.get("uuid")
            if not uuid:
                return self.unavailable("Missing scan identifier")
            # Wait for scan to complete (mirrors existing backend behavior)
            await asyncio.sleep(3)
            result = None
            for attempt in range(4):
                try:
                    r = await client.get(
                        f"https://urlscan.io/api/v1/result/{uuid}/",
                        headers={"API-Key": self.api_key},
                    )
                    if r.status_code == 404:
                        await asyncio.sleep(4)
                        continue
                    r.raise_for_status()
                    result = r.json()
                    break
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404 and attempt < 3:
                        await asyncio.sleep(4)
                        continue
                    raise
            if result is None:
                return self.unavailable("Scan result not ready")
            overall = result.get("verdicts", {}).get("overall", {})
            malicious = overall.get("malicious", False)
            score = overall.get("score")
            verdict = "malicious" if malicious else ("suspicious" if score and score >= 30 else "safe")
            return self.success(verdict, score=int(score) if score is not None else None,
                                details={"scan_id": uuid})
        except Exception as exc:  # noqa: BLE001
            logger.warning("urlscan.io failed: %s", redact_url(url))
            return self.unavailable(f"Provider request failed: {exc}")
