# ML Data Directory

This directory is intended for labeled training/evaluation datasets.

## IMPORTANT

No real phishing or benign dataset is shipped with this repository. Do NOT commit
datasets with restricted licenses, private scan history, or sensitive URLs here.

## Expected dataset format

A CSV file with two columns:

| Column | Description |
|--------|-------------|
| `url` | The URL string |
| `label` | `1` = phishing/malicious, `0` = benign/legitimate |

## Suggested sources (investigate access & usage terms yourself)

- **PhishTank** — community phishing feed (verify license before use)
- **OpenPhish** — phishing feed (subject to access/usage terms)
- **Tranco** — top domains list for benign samples
- Other properly licensed academic phishing datasets

## Preprocessing requirements (handled by ml/train.py)

- Remove duplicates (by URL)
- Handle missing values (drop rows with missing url/label)
- Check class imbalance
- Avoid train/test leakage (stratified split; final held-out test set)
- Save feature schema + model metadata

## Example

```csv
url,label
https://example.com/login,1
https://example.org,0
```

Train with:
```bash
cd ai_backend
python -m ml.train --data data/urls.csv --model-out ml/model.joblib --meta-out ml/model_meta.json
```
