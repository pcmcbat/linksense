# ML Pipeline, Training & Evaluation (Reproducible Procedure)

## Important constraints
- **No dataset or trained model is included.** Do not download or fabricate datasets/results in this repo.
- `ai_backend/ml/model.joblib` and `ai_backend/ml/model_meta.json` are not shipped; prediction reports ML unavailable until you train and provide artifacts.
- Any accuracy/precision/recall/F1/ROC-AUC/PR-AUC/calibration/latency numbers must come from **actual experiments on legitimately sourced data**.

## Dataset (user-supplied)
- Place labeled CSV at `ai_backend/data/urls.csv` (or pass `--data`).
- Required columns: `url`, `label` (`1`/phishing-malicious or `0`/benign/legitimate; `ml/train.py` normalizes common forms).
- Document for your experiment/report: source(s), collection dates, licenses/terms, label definitions, class distribution, deduping, and preprocessing.
- Candidate sources to evaluate (verify access/licensing): PhishTank, OpenPhish, Tranco (benign), and properly licensed academic datasets.

## Feature schema
- Implemented in `ai_backend/app/features.py` (`FEATURE_NAMES`, `extract_features`, `feature_vector`).
- Same pipeline must be used for training and inference; model metadata should record schema/version.

## Training (`ai_backend/ml/train.py`)
```powershell
cd ai_backend
python -m ml.train --data data/urls.csv --model-out ml/model.joblib --meta-out ml/model_meta.json
```
Current implementation:
- Loads/dedupes data, builds feature matrix, stratified train/val/test split.
- Compares baseline candidates (e.g. Logistic Regression, Random Forest, Gradient Boosting) and selects by validation performance (extend as needed).
- Calibrates probabilities and saves model + metadata (`model_name`, `model_version`, schema, training metadata/metrics where computed).

**Required research rigor (perform when running real experiments):** leakage prevention (domain/time-aware splits where possible), class-imbalance handling, untouched final test set, threshold selection on validation, reproducible seeds/environment, and full metric reporting.

## Evaluation framework (code support)
- `ai_backend/ml/evaluate.py`: metric helpers (accuracy/precision/recall/F1/confusion/ROC-AUC) and calibration utilities.
- **To complete Phase 8 properly, run and record (on real data/model):**
  - Baseline heuristic-only vs ML-only vs reputation-only vs hybrid
  - PR-AUC, ROC-AUC, FPR/FNR, confusion matrices, calibration curves/ECE
  - Prediction and provider latency measurements
  - Ablation studies (remove/weight components)
  - Robustness tests (punycode, encoding, misleading subdomains, long/IP URLs, suspicious params, shorteners, typosquatting, malformed inputs, provider outages/timeouts)
  - Graphs/tables generated from actual results only

## Suggested experiment output layout (create during real runs)
- `ai_backend/experiments/results/` — JSON/CSV metrics, plots generated from measured data
- `ai_backend/experiments/REPORT_NOTES.md` — methodology, environment, exact commands, and findings

No experiment outputs are committed here because no real experiments have been executed in this workspace.
