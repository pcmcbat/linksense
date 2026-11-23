"""Local heuristic URL analyzer.

Port of the existing LinkSense `analyzeUrlLocally` from background.js.
Preserved unchanged as the baseline scoring behavior (scores 0-100).
"""

import re
from typing import Dict, List
from urllib.parse import urlparse

TARGET_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal",
    "facebook", "instagram", "netflix", "linkedin", "dropbox",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
]


def _edit_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lc in enumerate(left, start=1):
        current = [i] + [0] * len(right)
        for j, rc in enumerate(right, start=1):
            cost = 0 if lc == rc else 1
            current[j] = min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost)
        previous = current
    return previous[-1]


def detect_safe_browsing_fixture(url: str) -> Dict | None:
    """Google Safe Browsing test fixture -> malicious (preserved behavior)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname.lower()
        pathname = parsed.pathname.lower()
        is_gst = hostname == "testsafebrowsing.appspot.com" and "/apiv4/" in pathname
        threat_type = re.search(
            r"(malware|phishing|social_engineering|unwanted_software|potentially_harmful_application)",
            pathname,
        )
        if is_gst and threat_type:
            return {
                "verdict": "malicious",
                "score": 100,
                "signals": ["Google Safe Browsing malware test fixture detected"],
                "source": "local",
            }
    except Exception:
        pass
    return None


def analyze_url_locally(url: str) -> Dict:
    """Run the existing LinkSense local heuristic analysis."""
    fixture = detect_safe_browsing_fixture(url)
    if fixture:
        return fixture

    try:
        parsed = urlparse(url)
    except Exception:
        return {"verdict": "safe", "score": 0, "signals": [], "source": "local"}

    hostname = (parsed.hostname or "").lower()
    full_url = url.lower()
    signals: List[str] = []
    score = 0

    def add_signal(points: int, label: str) -> None:
        nonlocal score
        score += points
        signals.append(label)

    # Raw IP address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        add_signal(30, "Raw IP address")
    # Non-standard port
    if parsed.port and str(parsed.port) not in ("80", "443"):
        add_signal(15, "Non-standard port")
    # Punycode / homograph
    if "xn--" in hostname:
        add_signal(30, "Punycode / homograph domain")
    # Unicode hostname
    if re.search(r"[^\x00-\x7F]", hostname):
        add_signal(25, "Unicode hostname")
    # Hidden credentials
    if parsed.username or parsed.password:
        add_signal(20, "Hidden credentials")
    # Deep subdomains
    if len(hostname.split(".")) > 4:
        add_signal(15, "Deep subdomains")
    # Long URL path
    if len(parsed.path or "") > 100:
        add_signal(10, "Long URL path")
    # Random URL string
    if re.search(r"[a-f0-9]{24,}|[A-Za-z0-9]{18,}", (parsed.path or "") + (parsed.query or "")):
        add_signal(10, "Random URL string")
    # URL shortener
    if hostname in URL_SHORTENERS:
        add_signal(8, "URL shortener")
    # Sensitive keyword
    if re.search(r"login|verify|secure|account|wallet|payment|password|signin", full_url):
        add_signal(8, "Sensitive keyword")

    # Target-brand typosquat (Levenshtein distance 1-2)
    domain_label = hostname.split(".")[-2] if hostname.count(".") >= 1 else hostname
    domain_label = re.sub(r"[^a-z]", "", domain_label)
    for brand in TARGET_BRANDS:
        distance = _edit_distance(domain_label, brand)
        if 0 < distance <= 2:
            add_signal(28, f"Possible {brand} typosquat")
            break

    verdict = "malicious" if score >= 60 else ("suspicious" if score >= 25 else "safe")
    return {
        "verdict": verdict,
        "score": min(100, score),
        "signals": signals,
        "source": "local",
    }
