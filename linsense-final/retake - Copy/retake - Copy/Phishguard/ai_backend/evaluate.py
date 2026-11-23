"""Evaluation script for LinkSense AI - compares detection methods."""

import json
import httpx
from typing import Dict, List

# Test URLs with known labels
TEST_URLS = [
    # Legitimate URLs
    ("https://www.google.com", "safe"),
    ("https://www.microsoft.com", "safe"),
    ("https://www.apple.com", "safe"),
    ("https://www.amazon.com", "safe"),
    ("https://www.paypal.com", "safe"),
    ("https://www.github.com", "safe"),
    ("https://stackoverflow.com", "safe"),
    ("https://www.wikipedia.org", "safe"),
    ("https://www.reddit.com", "safe"),
    ("https://www.youtube.com", "safe"),
    
    # Phishing URLs
    ("http://paypal.com.phishersite.com/login", "malicious"),
    ("https://secure-paypal.com.phishersite.com/verify", "malicious"),
    ("http://192.168.1.100/fakebank/login", "malicious"),
    ("https://xn--pple-43d.com/account", "malicious"),
    ("https://www.google.com.phishersite.com/signin", "malicious"),
    ("https://microsoft-security-alert.phishersite.com/verify", "malicious"),
    ("https://appleid.phishersite.com/unlock", "malicious"),
    ("https://amazon-security.phishersite.com/update", "malicious"),
    ("https://bit.ly/phishing-link", "malicious"),
    ("https://tinyurl.com/fake-login", "malicious"),
    ("https://paypal.com.verify-account.phishersite.com", "malicious"),
    ("https://www.google.com.account-recovery.phishersite.com", "malicious"),
]

BASE_URL = "http://127.0.0.1:8787"

def call_api(endpoint: str, url: str) -> Dict:
    """Call the API endpoint."""
    with httpx.Client(timeout=60.0) as client:
        try:
            r = client.post(f"{BASE_URL}{endpoint}", json={"url": url})
            return r.json()
        except httpx.ReadTimeout:
            return {"error": "timeout"}

def evaluate():
    """Run evaluation comparing different detection methods."""
    print("=" * 80)
    print("LINKSENSE AI - EVALUATION REPORT")
    print("=" * 80)
    
    results = []
    
    for url, true_label in TEST_URLS:
        print(f"\nTesting: {url}")
        print(f"  True label: {true_label}")
        
        # Call hybrid scan
        result = call_api("/api/scan", url)
        scan_result = result.get("result", {})
        
        verdict = scan_result.get("verdict", "unknown")
        risk_score = scan_result.get("risk_score", 0)
        ml_prob = scan_result.get("ml_probability", 0)
        heuristic_score = scan_result.get("heuristic_score", 0)
        classification = scan_result.get("classification", "Unknown")
        
        # Heuristic only
        heuristic_verdict = "safe"
        if heuristic_score >= 60:
            heuristic_verdict = "malicious"
        elif heuristic_score >= 25:
            heuristic_verdict = "suspicious"
        
        # ML only
        ml_verdict = "safe"
        if ml_prob >= 0.6:
            ml_verdict = "malicious"
        elif ml_prob >= 0.3:
            ml_verdict = "suspicious"
        
        print(f"  Hybrid: {verdict} (risk={risk_score}, ml={ml_prob:.2f}, heuristic={heuristic_score})")
        print(f"  Heuristic only: {heuristic_verdict} (score={heuristic_score})")
        print(f"  ML only: {ml_verdict} (prob={ml_prob:.2f})")
        
        results.append({
            "url": url,
            "true_label": true_label,
            "hybrid_verdict": verdict,
            "hybrid_risk_score": risk_score,
            "ml_verdict": ml_verdict,
            "ml_probability": ml_prob,
            "heuristic_verdict": heuristic_verdict,
            "heuristic_score": heuristic_score,
            "classification": classification,
        })
    
    # Calculate metrics
    print("\n" + "=" * 80)
    print("METRICS")
    print("=" * 80)
    
    def calculate_metrics(pred_labels: List[str], true_labels: List[str], label: str):
        tp = fp = tn = fn = 0
        for pred, true in zip(pred_labels, true_labels):
            if pred == "malicious" and true == "malicious":
                tp += 1
            elif pred == "malicious" and true == "safe":
                fp += 1
            elif pred == "safe" and true == "safe":
                tn += 1
            elif pred == "safe" and true == "malicious":
                fn += 1
            # Suspicious counts as malicious for binary classification
            elif pred == "suspicious" and true == "malicious":
                tp += 1
            elif pred == "suspicious" and true == "safe":
                fp += 1
        
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
    
    true_labels = [r["true_label"] for r in results]
    hybrid_labels = [r["hybrid_verdict"] for r in results]
    ml_labels = [r["ml_verdict"] for r in results]
    heuristic_labels = [r["heuristic_verdict"] for r in results]
    
    calculate_metrics(hybrid_labels, true_labels, "Hybrid (Heuristic + ML + Reputation)")
    calculate_metrics(ml_labels, true_labels, "ML Only")
    calculate_metrics(heuristic_labels, true_labels, "Heuristic Only")
    
    # Save detailed results
    with open("evaluation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("EVALUATION COMPLETE")
    print("=" * 80)
    print("Results saved to evaluation_results.json")

if __name__ == "__main__":
    evaluate()