"""ML training pipeline for LinkSense AI.

Reads a labeled CSV (columns: url,label), trains and compares candidate models,
calibrates the best one, and saves model.joblib + model_meta.json.

NOTE: This repository does NOT ship a real phishing/benign dataset. The user must
supply a CSV at ml/data/urls.csv (or pass --data). Dataset sources to investigate
include PhishTank, OpenPhish (subject to access/usage terms), and Tranco for benign
domains. Document source, collection date, license, label definitions, class
distribution, and preprocessing in ml/data/README.md.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.features import FEATURE_NAMES, feature_vector  # noqa: E402

MODEL_NAME = "RandomForestClassifier"
MODEL_VERSION = "linksense-ml-v1"


def load_data(data_path: str) -> pd.DataFrame:
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found: {data_path}")
    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns")
    df = df.dropna(subset=["url", "label"])
    df = df.drop_duplicates(subset=["url"])

    def norm_label(v):
        s = str(v).strip().lower()
        if s in ("1", "true", "yes", "phishing", "malicious", "bad"):
            return 1
        if s in ("0", "false", "no", "benign", "legitimate", "good", "safe"):
            return 0
        return -1

    df["label"] = df["label"].map(norm_label)
    df = df[df["label"] >= 0]
    return df


def build_X(df: pd.DataFrame) -> np.ndarray:
    return np.array([feature_vector(u) for u in df["url"].tolist()], dtype=float)


def train_and_evaluate(data_path: str, model_out: str = "ml/model.joblib",
                       meta_out: str = "ml/model_meta.json") -> Dict:
    df = load_data(data_path)
    y = df["label"].values
    X = build_X(df)

    # Train/validation/test split. Stratify to preserve class balance.
    # Final test set is held out and untouched until final evaluation.
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=0.2, random_state=42, stratify=y_trainval
    )

    candidates = {
        "RandomForest": RandomForestClassifier(n_estimators=200, max_depth=None,
                                               min_samples_split=4, random_state=42,
                                               n_jobs=-1),
        "LogisticRegression": LogisticRegression(max_iter=2000, random_state=42,
                                                 n_jobs=-1),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=200,
                                                       max_depth=3, random_state=42),
    }

    results = {}
    best_name = None
    best_auc = -1.0
    best_pipe = None

    for name, clf in candidates.items():
        pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
        pipe.fit(X_train, y_train)
        # Calibrate on validation set (isotonic)
        cal = CalibratedClassifierCV(pipe, method="isotonic", cv="prefit")
        cal.fit(X_val, y_val)
        proba = cal.predict_proba(X_val)[:, 1]
        auc = roc_auc_score(y_val, proba)
        results[name] = {"auc": float(auc)}
        if auc > best_auc:
            best_auc = auc
            best_name = name
            best_pipe = cal

    # Evaluate on held-out test set
    test_proba = best_pipe.predict_proba(X_test)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    metrics = {
        "accuracy": float(accuracy_score(y_test, test_pred)),
        "precision": float(precision_score(y_test, test_pred, zero_division=0)),
        "recall": float(recall_score(y_test, test_pred, zero_division=0)),
        "f1": float(f1_score(y_test, test_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, test_proba)),
        "confusion_matrix": confusion_matrix(y_test, test_pred).tolist(),
        "test_size": int(len(y_test)),
        "train_size": int(len(y_train)),
        "val_size": int(len(y_val)),
    }

    # Save model + metadata
    os.makedirs(os.path.dirname(model_out), exist_ok=True)
    joblib.dump(best_pipe, model_out)
    meta = {
        "model_name": best_name,
        "model_version": MODEL_VERSION,
        "feature_schema": FEATURE_NAMES,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "validation_auc": best_auc,
        "test_metrics": metrics,
        "class_distribution": {
            "benign": int((y == 0).sum()),
            "phishing": int((y == 1).sum()),
        },
        "thresholds": {
            "suspicious": 0.30,
            "malicious": 0.60,
        },
        "note": "Probabilities are calibrated estimates, not guaranteed attack probabilities.",
    }
    with open(meta_out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return {"best_model": best_name, "validation_auc": best_auc, "test_metrics": metrics,
            "model_path": model_out, "meta_path": meta_out}


def main() -> None:
    parser = argparse.ArgumentParser(description="Train LinkSense ML phishing detector")
    parser.add_argument("--data", required=True, help="Path to labeled CSV (url,label)")
    parser.add_argument("--model-out", default="ml/model.joblib")
    parser.add_argument("--meta-out", default="ml/model_meta.json")
    args = parser.parse_args()
    out = train_and_evaluate(args.data, args.model_out, args.meta_out)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

