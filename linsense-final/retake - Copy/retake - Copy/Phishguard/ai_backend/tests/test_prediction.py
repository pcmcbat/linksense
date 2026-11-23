"""Tests for ML prediction (graceful when model/training stack unavailable)."""

from ml.predict import MLPredictor


def test_predictor_without_model():
    p = MLPredictor(model_path="ml/nonexistent.joblib", meta_path="ml/nonexistent.json")
    assert p.is_available() is False
    out = p.predict("https://example.com")
    assert out["available"] is False
    assert out["error"] is not None


def test_model_info_without_model():
    p = MLPredictor(model_path="ml/nonexistent.joblib", meta_path="ml/nonexistent.json")
    info = p.model_info()
    assert "model_name" in info
    assert "model_version" in info
    assert "feature_schema" in info
