"""Tests for backend security helpers."""

from app.security import redact_url, validate_url_for_backend, is_private_or_resolved_private


def test_validate_rejects_missing():
    ok, reason = validate_url_for_backend("")
    assert not ok


def test_validate_rejects_non_http():
    ok, _ = validate_url_for_backend("ftp://example.com/file")
    assert not ok
    ok, _ = validate_url_for_backend("javascript:alert(1)")
    assert not ok


def test_validate_rejects_embedded_credentials():
    ok, reason = validate_url_for_backend("https://user:pass@example.com/")
    assert not ok
    assert "credential" in reason.lower()


def test_validate_rejects_private_ip_literals():
    for url in [
        "http://127.0.0.1/",
        "http://10.0.0.1/x",
        "http://192.168.1.1/",
        "http://[::1]/",
    ]:
        ok, _ = validate_url_for_backend(url)
        assert not ok, url


def test_validate_accepts_public_https():
    ok, reason = validate_url_for_backend("https://example.com/path?q=1")
    assert ok, reason


def test_redact_url_strips_credentials_and_query_shape():
    redacted = redact_url("https://user:secret@example.com/path?token=abc")
    assert "secret" not in redacted
    assert "token=abc" not in redacted
    assert "example.com" in redacted


def test_private_ip_detection():
    assert is_private_or_resolved_private("127.0.0.1")
    assert is_private_or_resolved_private("10.1.2.3")
    assert not is_private_or_resolved_private("8.8.8.8")
    assert not is_private_or_resolved_private("example.com")
