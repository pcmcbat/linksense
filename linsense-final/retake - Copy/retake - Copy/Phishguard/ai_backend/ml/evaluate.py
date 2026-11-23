"""Evaluation utilities for LinkSense AI models."""

import json
from typing import Dict, List, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def evaluate(y_true: List[int], y_pred: List[int], y_proba: List[float]) -> Dict:
    """Compute standard classification metrics."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_proba)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def calibration_report(y_true: List[int], y_proba: List[float], n_bins: int = 10) -> Dict:
    """Simple reliability-bin calibration report (expected calibration error)."""
    y_true = np.array(y_true)
    y_proba = np.array(y_proba)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    bin_details = []
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_proba >= lo) & (y_proba < hi) if i < n_bins - 1 else (y_proba >= lo) & (y_proba <= hi)
        if not mask.any():
            continue
        conf = float(y_proba[mask].mean())
        acc = float(y_true[mask].mean())
        ece += mask.mean() * abs(conf - acc)
        bin_details.append({"bin": f"{lo:.1f}-{hi:.1f}", "count": int(mask.sum()),
                            "accuracy": acc, "confidence": conf})
    return {"expected_calibration_error": float(ece), "bins": bin_details}
