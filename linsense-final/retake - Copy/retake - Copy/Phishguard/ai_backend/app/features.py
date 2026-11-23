"""Shared URL feature extraction pipeline.

This module extracts URL-based features used both for ML model training and for
real-time predictions. The same pipeline must be used at train time and inference
time so the model receives identical feature ordering and semantics.
"""

import re
from urllib.parse import urlparse

# Suspicious keywords commonly used in phishing URLs.
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "wallet", "payment",
    "password", "signin", "sign-in", "banking", "update", "confirm",
    "suspended", "alert", "security", "webscr", "paypal", "appleid",
    "microsoft", "google", "amazon", "netflix", "linkedin",
]

# Target brands for typosquat / brand-impersonation heuristic signals.
TARGET_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal",
    "facebook", "instagram", "netflix", "linkedin", "dropbox",
]

# Common URL shortener hostnames.
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc", "tr.im",
]

# Feature names in the fixed order used by the model. Keep this list stable and
# document any additions; the model artifact stores the schema it was trained on.
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "suspicious_keyword_count",
    "https",
    "ip_in_hostname",
    "punycode",
    "url_encoded",
    "unusual_port",
    "embedded_credentials",
    "path_length",
    "query_param_count",
    "domain_has_brand",
    "brand_edit_distance",
    "url_shortener",
    "path_depth",
]


def _edit_distance(left: str, right: str) -> int:
    """Levenshtein distance between two strings."""
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
            current[j] = min(
                current[j - 1] + 1,      # insertion
                previous[j] + 1,         # deletion
                previous[j - 1] + cost,  # substitution
            )
        previous = current
    return previous[-1]


def extract_features(url: str) -> dict:
    """Extract a fixed-length feature dictionary from a URL.

    All feature values are numeric. Missing/unparseable values default to 0 or
    False so the pipeline never fails on malformed input.
    """
    features = {name: 0 for name in FEATURE_NAMES}
    features["https"] = 0
    features["ip_in_hostname"] = 0
    features["punycode"] = 0
    features["url_encoded"] = 0
    features["unusual_port"] = 0
    features["embedded_credentials"] = 0
    features["domain_has_brand"] = 0
    features["url_shortener"] = 0

    if not url:
        return features

    try:
        parsed = urlparse(url)
    except Exception:
        return features

    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""
    full = url

    # URL length
    features["url_length"] = len(full)
    # Domain length
    features["domain_length"] = len(hostname)
    # Subdomain count
    try:
        import tldextract

        ext = tldextract.extract(hostname)
        subdomain = ext.subdomain or ""
        features["subdomain_count"] = len([s for s in subdomain.split(".") if s])
    except Exception:
        features["subdomain_count"] = hostname.count(".")
    # Dot count in hostname
    features["dot_count"] = hostname.count(".")
    # Hyphen count in hostname
    features["hyphen_count"] = hostname.count("-")
    # Digit count in hostname
    features["digit_count"] = sum(c.isdigit() for c in hostname)
    # Special character count in hostname (excluding alnum, dot, hyphen)
    features["special_char_count"] = sum(
        1 for c in hostname if not (c.isalnum() or c in ".-")
    )
    # Suspicious keyword count across full URL (lowercased)
    lowered = full.lower()
    features["suspicious_keyword_count"] = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered
    )
    # HTTPS availability
    features["https"] = 1 if scheme == "https" else 0
    # IP address in hostname
    features["ip_in_hostname"] = 1 if _is_ip(hostname) else 0
    # Punycode detection
    features["punycode"] = 1 if "xn--" in hostname else 0
    # URL encoding patterns
    features["url_encoded"] = 1 if "%" in full else 0
    # Unusual ports (not 80/443 and present)
    if port is not None and port not in (80, 443):
        features["unusual_port"] = 1
    # Embedded credentials
    features["embedded_credentials"] = 1 if (parsed.username or parsed.password) else 0
    # Path length
    features["path_length"] = len(path)
    # Query parameter count
    if query:
        features["query_param_count"] = len([p for p in query.split("&") if p])
    else:
        features["query_param_count"] = 0
    # Path depth
    features["path_depth"] = len([seg for seg in path.split("/") if seg])
    # Domain has a target brand token (brand impersonation indicator)
    domain_label = hostname.split(".")[-2] if hostname.count(".") >= 1 else hostname
    domain_label = re.sub(r"[^a-z]", "", domain_label)
    found_brand = False
    best_distance = 99
    for brand in TARGET_BRANDS:
        if brand in domain_label:
            found_brand = True
        dist = _edit_distance(domain_label, brand)
        if dist < best_distance:
            best_distance = dist
    features["domain_has_brand"] = 1 if found_brand else 0
    features["brand_edit_distance"] = best_distance if best_distance != 99 else 0
    # URL shortener
    features["url_shortener"] = 1 if hostname in URL_SHORTENERS else 0

    return features


def feature_vector(url: str) -> list:
    """Return features as a list in FEATURE_NAMES order (for model input)."""
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]


def _is_ip(host: str) -> bool:
    """Return True if host is an IPv4 or IPv6 literal address."""
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


