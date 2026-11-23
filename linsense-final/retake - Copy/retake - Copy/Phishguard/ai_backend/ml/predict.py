"""ML prediction: load trained model and produce calibrated phishing predictions."""

import json
import os
from typing import Any, Dict, List, Optional

# Optional ML stack. Guarded so the backend still runs if numpy/scikit-learn
# cannot be loaded in a restricted environment.
try:
    import joblib  # type: ignore
    import numpy as np  # type: ignore
    _ML_STACK_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    joblib = None  # type: ignore
    np = None  # type: ignore
    _ML_STACK_AVAILABLE = False

from app.features import FEATURE_NAMES, extract_features, feature_vector

MODEL_VERSION = "linksense-ml-v1"

# Thresholds for mapping calibrated probability -> classification.
# These are validated defaults; PHASE 5 replaces them with validation-derived values.
PROB_SUSPICIOUS = 0.30
PROB_MALICIOUS = 0.60


class ModelNotAvailableError(RuntimeError):
    """Raised when the ML model cannot be loaded."""


class MLPredictor:
    """Loads a trained sklearn pipeline and exposes predict_proba-based scoring."""

    def __init__(self, model_path: str = "ml/model.joblib", meta_path: str = "ml/model_meta.json"):
        self.model_path = model_path
        self.meta_path = meta_path
        self.model = None
        self.meta: Dict[str, Any] = {}
        self.loaded = False
        self._load()

    def _load(self) -> None:
        if not _ML_STACK_AVAILABLE:
            self.loaded = False
            return
        if not os.path.exists(self.model_path):
            self.loaded = False
            return
        try:
            self.model = joblib.load(self.model_path)
        except Exception:
            self.model = None
            self.loaded = False
            return
        if os.path.exists(self.meta_path):
            try:
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    self.meta = json.load(f)
            except Exception:
                self.meta = {}
        self.loaded = self.model is not None

    def is_available(self) -> bool:
        return self.loaded and self.model is not None

    def model_info(self) -> Dict[str, Any]:
        return {
            "model_name": self.meta.get("model_name", "RandomForestClassifier"),
            "model_version": self.meta.get("model_version", MODEL_VERSION),
            "feature_schema": self.meta.get("feature_schema", FEATURE_NAMES),
            "training_metadata": self.meta.get("training_metadata", {}),
        }

    def predict(self, url: str) -> Dict[str, Any]:
        """Return prediction dict: class, calibrated probability, top features."""
        result: Dict[str, Any] = {
            "prediction": "safe",
            "probability": 0.0,
            "model_version": MODEL_VERSION,
            "top_features": [],
            "available": False,
            "error": None,
        }
        if not _ML_STACK_AVAILABLE:
            result["error"] = "ML stack (numpy/scikit-learn) not available in this environment"
            return result
        if not self.is_available():
            result["error"] = "ML model not available"
            return result
        try:
            X = np.array([feature_vector(url)], dtype=float)
            # Calibrated probability of the positive (phishing/malicious) class.
            proba = float(self.model.predict_proba(X)[0][1])
            pred_class = int(self.model.predict(X)[0])
            label = "malicious" if pred_class == 1 else "safe"
            # Map to three-way classification using calibrated thresholds.
            if proba >= PROB_MALICIOUS:
                label = "malicious"
            elif proba >= PROB_SUSPICIOUS:
                label = "suspicious"
            else:
                label = "safe"
            result["prediction"] = label
            result["probability"] = round(proba, 4)
            result["available"] = True
            result["top_features"] = self._top_features(url)
        except Exception as exc:  # pragma: no cover - defensive
            result["error"] = f"Prediction failed: {exc}"
        return result

    def _top_features(self, url: str) -> List[Dict[str, Any]]:
        """Return a few salient features as contributing indicators (not SHAP values)."""
        feats = extract_features(url)
        # Heuristic salience: nonzero high-impact features.
        salient = []
        for name in ["ip_in_hostname", "punycode", "url_shortener", "unusual_port",
                     "embedded_credentials", "subdomain_count", "suspicious_keyword_count",
                     "url_length", "domain_length"]:
            val = feats.get(name, 0)
            if val:
                salient.append({"feature": name, "value": val})
        # Sort by a crude impact so the most suspicious show first.
        impact_order = {
            "ip_in_hostname": 5, "punycode": 5, "embedded_credentials": 4,
            "unusual_port": 3, "url_shortener": 3, "subdomain_count": 2,
            "suspicious_keyword_count": 2, "url_length": 1, "domain_length": 1,
        }
        salient.sort(key=lambda item: impact_order.get(item["feature"], 0), reverse=True)
        return salient[:6]
