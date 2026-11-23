"""MetaDefender Cloud provider adapter (ported from existing Node backend)."""

import asyncio
import logging

import httpx

from app.reputation import BaseProvider
from app.security import redact_url

logger = logging.getLogger("linksense.providers.metadefender")


class MetaDefenderProvider(BaseProvider):
    def __init__(self, api_key: str, timeout: float = 10.0):
        super().__init__("MetaDefender Cloud", timeout)
        self.api_key = api_key

    async def check(self, url: str, hostname: str):
        if not self.api_key:
            return self.unavailable("API key is not configured")
        client = await self._get_client()
        try:
            r = await client.post(
                "https://api.metadefender.com/v4/url",
                headers={"apikey": self.api_key},
                json={"url": url},
            )
            if r.status_code >= 400:
                return self.unavailable(f"HTTP {r.status_code}")
            data = r.json()
            # Some responses return immediate data array
            if isinstance(data.get("data"), list) and data["data"]:
                item = data["data"][0]
                lookup = item.get("lookup_results") or {}
                detected = lookup.get("detected_by")
                if detected is None:
                    detected = (item.get("scan_results") or {}).get("total_detected_avs", 0)
                try:
                    detected = int(detected or 0)
                except (TypeError, ValueError):
                    detected = 0
                verdict = "malicious" if detected > 0 else "safe"
                return self.success(verdict, score=detected, details={"detections": detected})
            data_id = data.get("data_id")
            if not data_id:
                return self.unavailable("Missing scan identifier")
            report = None
            for attempt in range(5):
                rr = await client.get(
                    f"https://api.metadefender.com/v4/url/{data_id}",
                    headers={"apikey": self.api_key},
                )
                if rr.status_code >= 400:
                    return self.unavailable(f"HTTP {rr.status_code}")
                report = rr.json()
                progress = (report.get("scan_results") or {}).get("progress_percentage")
                if progress is not None and float(progress) >= 100:
                    break
                if attempt < 4:
                    await asyncio.sleep(2)
            if report is None:
                return self.unavailable("Scan report unavailable")
            scan_results = report.get("scan_results") or {}
            detected = scan_results.get("total_detected_avs", 0)
            total = scan_results.get("total_avs", 0)
            if not isinstance(detected, (int, float)):
                return self.unavailable("Invalid MetaDefender response")
            verdict = "malicious" if detected > 0 else "safe"
            return self.success(verdict, score=int(detected),
                                details={"detections": int(detected), "engines": int(total or 0)})
        except Exception as exc:  # noqa: BLE001
            logger.warning("MetaDefender Cloud failed for %s: %s", redact_url(url), exc)
            return self.unavailable(f"Provider request failed: {exc}")
