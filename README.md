# IoT/IIoT Intrusion Detection — Four-Model Comparison & Leakage-Sanitized PP-PSFE Framework

## Project Description
This project investigates multi-class (15-category: Normal + 14 cyberattack types) intrusion detection on the **Edge-IIoTset** benchmark dataset ([Ferrag et al., *IEEE Access*, 2022](https://doi.org/10.1109/ACCESS.2022.3165809)). Beyond comparing four distinct machine learning paradigms — **Multinomial Logistic Regression (Baseline)**, **Random Forest**, **XGBoost**, and **LightGBM** — this repository identifies and resolves a critical **Serialization Shortcut Leakage & Clean-Feature Blindness** gap in standard Edge-IIoTset pipelines via **Privacy-Preserving Protocol-Header Structural Feature Engineering (PP-PSFE)** and **Native C++ TreeSHAP Explainability**.

## Dataset
**Name:** Edge-IIoTset — A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications (Ferrag et al., *IEEE Access*, 2022)  
**DOI:** `10.1109/ACCESS.2022.3165809`

**Sources:**
- Kaggle: https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot
- IEEE DataPort: https://dx.doi.org/10.21227/mbc1-1h68

Place `ML-EdgeIIoT-dataset.csv` inside `dataset/ML-EdgeIIoT-dataset.csv` (or `dataset/Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv`).

## Models Evaluated
1. **Multinomial Logistic Regression** (`sklearn.linear_model.LogisticRegression`) — Parametric linear baseline.
2. **Random Forest** (`sklearn.ensemble.RandomForestClassifier`) — Parallel variance-reducing bagging ensemble with balanced class weights.
3. **XGBoost** (`xgboost.XGBClassifier`) — Depth-wise second-order regularized gradient boosted trees.
4. **LightGBM** (`lightgbm.LGBMClassifier`) — Leaf-wise histogram-binned gradient boosting with GOSS/EFB for edge efficiency.

## Key Methodological Contributions
1. **Serialization Leakage Sanitization:** Canonicalizes mixed-type null representations (`"0"` vs. `"0.0"`) across 7 categorical protocol columns, repairs TShark column-shift corruption in `dns.qry.name.len`, removes 8 zero-variance constant features (`mbtcp.*`, `icmp.unused`, `http.tls_port`, `dns.qry.type`, `dns.retransmit_request_in`, `mqtt.msg_decoded_as`), and enforces strict post-split transformation fitting.
2. **Privacy-Preserving Protocol-Header Structural Feature Engineering (PP-PSFE):** Extracts 24 $O(1)$-computable transport-port, TCP-option/payload entropy, and application-layer lexical anomaly features before dropping high-cardinality identifier columns.
3. **Exact Native TreeSHAP Explainability:** Computes exact multi-class Shapley Additive Explanations (`pred_contribs=True`) directly from the compiled gradient booster.

## Experimental Results (15-Class Multiclass Classification)

### A. Proposed Leakage-Sanitized + PP-PSFE Framework (62 Clean Features)
| Model | Test Accuracy | Precision (Wt) | Recall (Wt) | F1-Score (Wt) | Macro F1-Score | ROC-AUC (Wt) | PR-AUC (Macro) | Overfitting Gap | Train Time (s) | Inference (ms/1k) |
|---|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression (Baseline) | 84.87% | 0.8492 | 0.8487 | 0.8479 | 0.8419 | 0.9829 | 0.8656 | +0.0016 | 17.61s | 0.57 ms |
| Random Forest | 94.38% | 0.9462 | 0.9438 | 0.9438 | 0.9414 | 0.9978 | 0.9768 | +0.0020 | 3.27s | 8.13 ms |
| LightGBM | 96.33% | 0.9641 | 0.9633 | 0.9632 | 0.9596 | 0.9991 | 0.9888 | +0.0210 | 7.19s | 17.06 ms |
| **XGBoost (Best Model)** | **96.49%** | **0.9658** | **0.9649** | **0.9649** | **0.9618** | **0.9991** | **0.9874** | **+0.0057** | **11.44s** | **3.36 ms** |

### B. Ablation Across Preprocessing Regimes (Test Accuracy / Macro-F1)
| Model | Regime A: Unsanitized Baseline (46 Feats) | Regime B: Leakage-Sanitized Only (38 Feats) | Regime C1: Strict Service-Tier PP-PSFE (56 Feats) | Regime C2: Full PP-PSFE (62 Feats) |
|---|---|---|---|---|
| Logistic Regression | 77.05% / 0.7425 | 58.84% / 0.5580 | 73.59% / 0.7199 | **84.87% / 0.8419** |
| Random Forest | 94.40% / 0.9196 | 87.14% / 0.8700 | 91.56% / 0.9149 | **94.38% / 0.9414** |
| LightGBM | 94.60% / 0.9257 | 88.08% / 0.8488 | 92.62% / 0.9228 | **96.33% / 0.9596** |
| **XGBoost** | 94.90% / 0.9356 | 89.01% / 0.8913 | 92.71% / 0.9244 | **96.49% / 0.9618** |

## How to Run
```bash
pip install -r requirements.txt
python intrusion_detection.py
python -m unittest discover -s tests -v
```
