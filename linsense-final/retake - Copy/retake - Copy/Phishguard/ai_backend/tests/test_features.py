"""Tests for URL feature extraction."""

from app.features import FEATURE_NAMES, extract_features, feature_vector


def test_extract_features_returns_fixed_schema():
    f = extract_features("https://example.com/page")
    assert set(f.keys()) == set(FEATURE_NAMES)
    assert len(f) == len(FEATURE_NAMES)


def test_extract_features_malformed_url():
    f = extract_features("")
    assert all(v == 0 for v in f.values())
    f = extract_features("not-a-url")
    assert isinstance(f["url_length"], int)


def test_extract_features_ip_address():
    f = extract_features("http://1.2.3.4/login")
    assert f["ip_in_hostname"] == 1


def test_extract_features_punycode():
    f = extract_features("https://xn--pple-43d.com")
    assert f["punycode"] == 1


def test_extract_features_https():
    f = extract_features("https://example.com")
    assert f["https"] == 1
    f2 = extract_features("http://example.com")
    assert f2["https"] == 0


def test_extract_features_unusual_port():
    f = extract_features("https://example.com:8443/")
    assert f["unusual_port"] == 1
    f2 = extract_features("https://example.com:443/")
    assert f2["unusual_port"] == 0


def test_feature_vector_order():
    v = feature_vector("https://example.com")
    assert len(v) == len(FEATURE_NAMES)
    assert all(isinstance(x, (int, float)) for x in v)


def test_suspicious_keywords():
    f = extract_features("https://example.com/login/verify/account")
    assert f["suspicious_keyword_count"] >= 1


def test_url_shortener():
    f = extract_features("https://bit.ly/abc")
    assert f["url_shortener"] == 1
