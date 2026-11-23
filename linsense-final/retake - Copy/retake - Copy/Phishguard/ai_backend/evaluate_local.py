"""Evaluation script for LinkSense AI - tests ML and heuristic locally."""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))

from app.features import feature_vector, FEATURE_NAMES
from app.heuristic import analyze_url_locally
from ml.predict import MLPredictor

# Test URLs with known labels
TEST_URLS = [
    # Legitimate URLs
    ("https://www.google.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.apple.com", 0),
    ("https://www.amazon.com", 0),
    ("https://www.paypal.com", 0),
    ("https://www.github.com", 0),
    ("https://stackoverflow.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.reddit.com", 0),
    ("https://www.youtube.com", 0),
    ("https://www.twitter.com", 0),
    ("https://www.cloudflare.com", 0),
    ("https://www.adobe.com", 0),
    ("https://www.salesforce.com", 0),
    ("https://aws.amazon.com", 0),
    ("https://cloud.google.com", 0),
    ("https://www.digitalocean.com", 0),
    ("https://api.github.com", 0),
    ("https://fonts.googleapis.com", 0),
    ("https://www.linkedin.com", 0),
    
    # Phishing URLs
    ("http://paypal.com.phishersite.com/login", 1),
    ("https://secure-paypal.com.phishersite.com/verify", 1),
    ("http://192.168.1.100/fakebank/login", 1),
    ("https://xn--pple-43d.com/account", 1),
    ("https://www.google.com.phishersite.com/signin", 1),
    ("https://microsoft-security-alert.phishersite.com/verify", 1),
    ("https://appleid.phishersite.com/unlock", 1),
    ("https://amazon-security.phishersite.com/update", 1),
    ("https://bit.ly/phishing-link", 1),
    ("https://tinyurl.com/fake-login", 1),
    ("https://paypal.com.verify-account.phishersite.com", 1),
    ("https://www.google.com.account-recovery.phishersite.com", 1),
    ("https://secure.banking.phishersite.com/login", 1),
    ("https://login.verify.phishersite.com/account", 1),
    ("https://account.secure.phishersite.com/verify", 1),
    ("https://wallet.payment.phishersite.com/confirm", 1),
    ("https://password.reset.phishersite.com/change", 1),
    ("https://signin.security.phishersite.com/alert", 1),
    ("https://banking.update.phishersite.com/info", 1),
    ("http://1.2.3.4/phishing", 1),
]

def calculate_metrics(predictions, true_labels, label):
    """Calculate precision, recall, F1, accuracy."""
    tp = fp = tn = fn = 0
    for pred, true in zip(predictions, true_labels):
        if pred == 1 and true == 1:
            tp += 1
        elif pred == 1 and true == 0:
            fp += 1
        elif pred == 0 and true == 0:
            tn += 1
        elif pred == 0 and true == 1:
            fn += 1
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\n{label}:")
    print(f"  TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"  Accuracy:  {accuracy:.2%}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  F1-Score:  {f1:.2%}")
    
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}

def evaluate():
    """Run evaluation comparing ML and heuristic."""
    print("=" * 80)
    print("LINKSENSE AI - EVALUATION REPORT (Local Testing)")
    print("=" * 80)
    
    # Load model
    predictor = MLPredictor(
        model_path="ml/model.joblib",
        meta_path="ml/model_meta.json"
    )
    
    print(f"\nModel loaded: {predictor.is_available()}")
    print(f"Model info: {predictor.model_info()}")
    
    results = []
    
    for url, true_label in TEST_URLS:
        # Heuristic analysis
        heuristic_result = analyze_url_locally(url)
        heuristic_score = heuristic_result["score"]
        heuristic_pred = 1 if heuristic_score >= 25 else 0  # Suspicious threshold
        
        # ML prediction
        ml_result = predictor.predict(url)
        ml_prob = ml_result["probability"]
        ml_pred = 1 if ml_prob >= 0.5 else 0
        
        # Hybrid (simple: if either says phishing)
        hybrid_pred = 1 if (heuristic_pred == 1 or ml_pred == 1) else 0
        
        results.append({
            "url": url,
            "true_label": true_label,
            "heuristic_score": heuristic_score,
            "heuristic_pred": heuristic_pred,
            "ml_probability": ml_prob,
            "ml_pred": ml_pred,
            "hybrid_pred": hybrid_pred,
        })
        
        status = "OK" if (hybrid_pred == true_label) else "FAIL"
        print(f"{status} {url[:50]:50s} | true={true_label} | h={heuristic_pred}({heuristic_score:2d}) | ml={ml_pred}({ml_prob:.2f}) | hybrid={hybrid_pred}")
    
    true_labels = [r["true_label"] for r in results]
    
    print("\n" + "=" * 80)
    print("METRICS")
    print("=" * 80)
    
    calculate_metrics([r["heuristic_pred"] for r in results], true_labels, "Heuristic Only")
    calculate_metrics([r["ml_pred"] for r in results], true_labels, "ML Only")
    calculate_metrics([r["hybrid_pred"] for r in results], true_labels, "Hybrid (Heuristic + ML)")
    
    # Save results
    with open("evaluation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("EVALUATION COMPLETE")
    print("=" * 80)
    print("Results saved to evaluation_results.json")

if __name__ == "__main__":
    evaluate()