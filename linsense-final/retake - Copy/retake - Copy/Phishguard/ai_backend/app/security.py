"""Security utilities: SSRF protection, URL redaction, input validation."""

import ipaddress
import logging
import re
from typing import Tuple
from urllib.parse import urlparse

logger = logging.getLogger("linksense.security")

# Reserved/private IP ranges that must not be targeted by backend-initiated fetches.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"), # 6to4 relay anycast
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),# TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"), # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),    # multicast
    ipaddress.ip_network("240.0.0.0/4"),    # reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),       # unique local
    ipaddress.ip_network("fe80::/10"),      # link-local
    ipaddress.ip_network("2001:db8::/32"),  # documentation
]

_URL_REDACT_PATTERN = re.compile(r"://[^@]+@")  # strip user:pass@


def redact_url(url: str) -> str:
    """Return a URL with embedded credentials and query fragments redacted for safe logging."""
    try:
        parsed = urlparse(url)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc += f":{parsed.port}"
        # Rebuild without username/password and without query
        safe = f"{parsed.scheme}://{netloc}{parsed.path or '/'}"
        return safe
    except Exception:
        return "<unparseable-url>"


def is_private_or_resolved_private(host: str) -> bool:
    """Return True if host is a private/reserved IP or cannot be resolved to a public IP."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A hostname: treat as potentially public (DNS resolution happens per-provider).
        # Backend must not *initiate* fetches to bare hostnames without provider validation.
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)


def validate_url_for_backend(url: str) -> Tuple[bool, str]:
    """Validate that a user-supplied URL is safe for the backend to process.

    Returns (ok, reason). Rejects non-HTTP(S), embedded credentials, and URLs
    whose hostname resolves to a private/reserved IP (SSRF defense).
    """
    if not url or not url.strip():
        return False, "URL is required"
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        return False, "Only HTTP or HTTPS URLs are supported"
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL"
    if parsed.username or parsed.password:
        return False, "Embedded credentials are not allowed"
    if not parsed.hostname:
        return False, "URL has no hostname"
    # Block direct private IP targets (SSRF). Hostnames are allowed; individual
    # providers perform their own DNS + privacy checks before contacting targets.
    if is_private_or_resolved_private(parsed.hostname):
        return False, "Private or reserved IP addresses are not allowed"
    return True, ""


def mask_api_key(key: str) -> str:
    """Mask an API key for safe logging/display."""
    if not key:
        return "<not-configured>"
    if len(key) <= 4:
        return "****"
    return f"****{key[-4:]}"
