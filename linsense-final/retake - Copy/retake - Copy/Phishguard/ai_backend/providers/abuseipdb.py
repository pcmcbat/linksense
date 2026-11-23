"""AbuseIPDB provider adapter (ported from existing Node backend)."""

import asyncio
import logging
import ipaddress

import httpx

from app.reputation import BaseProvider
from app.security import redact_url

logger = logging.getLogger("linksense.providers.abuseipdb")


class AbuseIPDBProvider(BaseProvider):
    def __init__(self, api_key: str, timeout: float = 10.0):
        super().__init__("AbuseIPDB", timeout)
        self.api_key = api_key

    async def check(self, url: str, hostname: str):
        if not self.api_key:
            return self.unavailable("API key is not configured")
        client = await self._get_client()
        try:
            # Resolve hostname to public IPv4 addresses
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(
                hostname, None, family=__import__("socket").AF_INET
            )
            ips = []
            seen = set()
            for info in infos:
                addr = info[4][0]
                try:
                    ip = ipaddress.ip_address(addr)
                except ValueError:
                    continue
                if ip.version == 4 and not (ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local) and str(ip) not in seen:
                    ips.append(str(ip))
                    seen.add(str(ip))
                if len(ips) >= 2:
                    break
            if not ips:
                return self.unavailable("No public IPv4 address found")
            scores = []
            for ip in ips:
                params = {"ipAddress": ip, "maxAgeInDays": "90"}
                r = await client.get("https://api.abuseipdb.com/api/v2/check",
                                     params=params,
                                     headers={"Key": self.api_key, "Accept": "application/json"})
                if r.status_code >= 400:
                    return self.unavailable(f"HTTP {r.status_code}")
                data = r.json()
                score = data.get("data", {}).get("abuseConfidenceScore")
                if score is None:
                    return self.unavailable("Invalid AbuseIPDB response")
                scores.append(score)
            score = max(scores)
            verdict = "malicious" if score >= 75 else ("suspicious" if score >= 50 else "safe")
            return self.success(verdict, score=int(score), details={"checked_ips": len(ips)})
        except Exception as exc:  # noqa: BLE001
            logger.warning("AbuseIPDB failed for %s: %s", redact_url(url), exc)
            return self.unavailable(f"Provider request failed: {exc}")