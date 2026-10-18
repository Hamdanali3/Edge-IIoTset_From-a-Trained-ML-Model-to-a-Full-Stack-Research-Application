# Edge-IIoTset PhD Research Project — Full Discussion Log

*Consolidated from all conversation sessions. Last updated: 18 October 2026.*

---

## 1. Project Context

- Student: 7th-semester Software Engineering, preparing a PhD application abroad.
- Goal shifted from an unrealistic "3–4 IEEE papers in final year" to a realistic target: **1–2 strong papers** (conference + journal) plus a semester DevOps/ML lab project.
- Chosen interest area: AI/ML applied to IoT/IIoT cybersecurity.

---

## 2. Dataset and Base Paper

**Paper:** Ferrag et al., *"Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications for Centralized and Federated Learning,"* IEEE Access, 2022.
DOI: 10.1109/ACCESS.2022.3165809 · Dataset DOI: 10.21227/mbc1-1h68 · Kaggle mirror available.

- Multi-layer IoT/IIoT testbed (cloud, network, fog, edge), 10+ device types.
- `ML-EdgeIIoT-dataset.csv`: 157,800 rows, 61–63 columns, 15 classes (1 Normal + 14 attacks across DoS/DDoS, information gathering, MITM, injection, malware).
- `DNN-EdgeIIoT-dataset.csv`: ~2.2M rows, same schema, larger scale.
- Original baselines (15-class, centralized): DT 67.11%, RF 80.83%, SVM 77.61%, KNN 79.18%, DNN 94.67%.
- Official preprocessing recipe (Readme Step 5) dummy-encodes 7 categorical columns, including the 4 that turned out to leak the label (see §4).

**Dataset verification (18 Oct 2026):** the student's own uploaded `Selected_dataset_for_ML_and_DL.rar` was unpacked and checked directly. Confirmed columns include the 4 leaking fields in raw (not yet dummy-encoded) form, and the placeholder split was reproduced exactly on this copy:

| Column | Normal-traffic placeholder | Attack-traffic placeholder |
|---|---|---|
| `dns.qry.name.len` | `"0"` (24,272 rows) | `"0.0"` (133,272 rows) |
| `mqtt.conack.flags` | `"0"` (23,012 rows) | `"0.0"` (133,499 rows) |
| `mqtt.protoname` | `"0"` (23,051 rows) | `"0.0"` (133,499 rows) |
| `mqtt.topic` | `"0"` (23,055 rows) | `"0.0"` (133,499 rows) |

This is the same artifact described in the literature (§4) — confirmed, not hypothetical, on the student's actual file.

---

## 3. Work Already Built

### 3.1 ML pipeline (RF vs XGBoost, 15-class)
- `/mnt/user-data/outputs/Edge_IIoTset_RF_vs_XGBoost.ipynb` — Colab notebook.
- `/mnt/user-data/outputs/edge_iiotset_rf_vs_xgboost.py` — plain Python fallback.
- 80/20 stratified split, Precision/Recall/F1/ROC-AUC, explicit overfitting-gap check (>5% flagged), best model exported as a `.pkl` bundle (model + scaler + label encoder + feature columns).
- **Known issue (critical):** the current `drop_candidates` list does **not** drop the 4 leaking columns — results from this pipeline as it stands are likely leakage-inflated and need the Protocol A/B rework described in §5.

### 3.2 DevOps GitHub lab repo
`/mnt/user-data/outputs/IoT-Intrusion-Detection-Edge-IIoTset.zip`, built against the uploaded "Dev-Ops Lab 4 – GitHub" PDF requirements:
- `intrusion_detection.py` (main script), `intrusion_detection_colab.ipynb`
- `utils.py` with `check_overfitting()` and `normalize_score()` (genuinely used, not a CI-only demo)
- `tests/test_utils.py` (8 passing unit tests)
- `.github/workflows/python-test.yml` CI workflow
- `requirements.txt`, `.gitignore`, full `README.md`

### 3.3 Literature review
`/mnt/user-data/outputs/Related_Work_Literature_Review.md` — 8 papers (2022–2026) on Edge-IIoTset/XGBoost/IIoT IDS, including Gaber et al. 2025 (XGBoost/CatBoost/LightGBM), Hasan et al. 2025 (lightweight autoencoder, arXiv:2501.15266), a cross-domain generalization paper (arXiv:2607.00553), an XAI paper (arXiv:2501.11618).

---

## 4. The Major Finding — Data Leakage in Edge-IIoTset

**Paper:** Galal, *"Provenance, Not Behaviour: A Serialisation Artifact in Edge-IIoTset and a Leakage-Free Benchmark for Precision-Agriculture Intrusion Detection,"* arXiv:2608.15761 (16 Aug 2026). Code: github.com/MostafaGalal1/agriedge.

- Edge-IIoTset's official preprocessing recipe dummy-encodes 4 columns — `dns.qry.name.len`, `mqtt.conack.flags`, `mqtt.protoname`, `mqtt.topic` — that turn out to be a near-perfect label proxy: a missing-field placeholder is written as the string `"0"` on the normal-traffic branch of the dataset build and `"0.0"` on the attack branch. This is a **build/serialization artifact**, not real network signal.
- Single-column accuracy on the artifact alone: 1.0000. Separation rate: 1.0000. NMI up to 0.9859.
- Under the buggy "as-distributed" protocol, 5 of 6 tested models (DT, RF, Hist-Gradient-Boosting, Logistic Regression, Naive Bayes) score **exactly** 1.0000 ± 0.0000 accuracy across 15-fold CV; MLP scores 0.99998.
- Under Galal's corrected protocol (canonicalize placeholders to one sentinel, deduplicate before split), the best model (Hist-GB) drops to 0.9503 ± 0.0011 macro-F1; Naive Bayes ("leakage canary") collapses to 0.6995 macro-F1.
- Confirmed at scale on the 2.2M-row DNN subset too. Leak is encoding-agnostic (one-hot/label/ordinal/frequency all leak identically).
- **XGBoost was never tested** in this paper — the confirmed open gap.
- Galal also built a leakage-free "AgriEdge" benchmark (1,276,122 rows, 5 devices) from raw captures; found generalization fails at the perception→actuation (Modbus) layer boundary, and that federated learning's real bottleneck is LoRaWAN bandwidth, not non-IID heterogeneity.
- Suspects (not confirmed) that Hasan et al. 2025's 99.94%-accuracy paper may be exposed to the same artifact.

### 4.1 Deeper literature check (alphaXiv / Consensus / SciSpace, Oct 2026)

A second, independent team found the **same exact artifact**:

- **Dhaou (2026), "Correlation-Based Leakage Screening is Insufficient for IoT/IIoT Intrusion-Detection Benchmarks," IEEE Access** — identifies the identical 4 columns via correlation screening, mutual information, recursive feature elimination, and adversarial validation; uses SHAP to characterize the *corrected* model's decision basis. Tests Random Forest, a generic "gradient boosting" model (not confirmed as the XGBoost library by name), Logistic Regression, MLP. **Still no confirmed XGBoost run.**

Two further 2026 papers put XGBoost, SHAP and Edge-IIoTset together but miss or sidestep this exact artifact:

- **Gholamrezazadeh & Montazerolghaem (2026), "XAI FL-IDS"** — runs XGBoost with SHAP (TreeExplainer) on Edge-IIoTset in a federated-learning setting, reports accuracy "over 99%, at times reaching 100%" — a strong real-world symptom of this leak — **without ever auditing for it**.
- **Alqahtani et al. (2026), *Sensors*, DOI 10.3390/s26175437** — runs XGBoost with SHAP/LIME on Edge-IIoTset under a protocol they call "leakage-free," but their fix addresses **resampling before the train/test split** — a different leakage mechanism — not the categorical-placeholder artifact. Their Edge-IIoTset numbers are therefore likely still exposed to it.

**Net effect on novelty:** the artifact is now independently confirmed twice (Galal, Dhaou), and two of the most relevant XGBoost+SHAP+Edge-IIoTset papers in current circulation demonstrably miss or sidestep it. The gap narrows from "nobody has run XGBoost on Edge-IIoTset" (false) to the precise, still-open claim: **nobody has run XGBoost under both the buggy and the corrected protocol for this specific artifact, paired with a before/after SHAP comparison.** Confidence: high.

---

## 5. Novel Contribution Roadmap (agreed)

| # | Contribution | Status |
|---|---|---|
| 1 (core) | XGBoost under Protocol A (buggy/as-distributed) vs Protocol B (corrected) | Pending implementation |
| 2 (strongly recommended) | SHAP before/after comparison — visual proof of feature-reliance shift | Pending implementation |
| 3 (optional/bonus) | XGBoost edge-deployment cost (model size, latency) on corrected data | Pending |
| 4 (optional/bonus) | Rebuild the `.pkl` + deployment pipeline on the corrected model | Pending |

**Minimum viable paper** = Contribution #1 + #2.

**Proposed title:** *"Boosting Through the Leak: Auditing XGBoost and Explaining Feature Reliance Before and After Correcting a Label-Leakage Artifact in Edge-IIoTset."*

### Research questions
- **RQ1:** Does XGBoost also reach ≈1.0000 accuracy under the buggy protocol, matching the other model families Galal already tested?
- **RQ2:** After correction, how much does XGBoost's macro-F1 drop vs. Random Forest, and does the *gap* between them change?
- **RQ3:** Does SHAP attribution visibly shift away from the 4 leaking columns toward genuine network-behavior features (`tcp.flags`, `icmp.checksum`, etc.) after correction — and does the shift look different for XGBoost vs. RF?

### Models to compare (finalized)
| Model | Role |
|---|---|
| **XGBoost** | Primary model under audit |
| **Random Forest** | Comparison baseline (used by Galal and Dhaou) |
| **Logistic Regression** | Linear baseline — *not* Linear Regression, since this is 15-class classification, not a numeric-prediction task |
| **Naive Bayes** | Leakage "canary" — confirms the corrected pipeline reproduces Galal's known collapse (0.6995 macro-F1) before trusting new XGBoost numbers |
| SHAP (TreeExplainer) | Explainability technique (not a classifier), used for Contribution #2 |

Deep learning models (DNN, autoencoders) are deliberately excluded from the core contribution.

**Expected (not yet proven) pattern:** based on Galal's corrected-protocol results, tree ensembles should clearly outperform the linear baseline, and Naive Bayes should collapse hardest. XGBoost is hypothesized to edge out Random Forest slightly on the corrected protocol (gradient boosting's residual-learning advantage) — this is a hypothesis to be tested, not a result.

### Experimental design summary
- **Dataset file:** `ML-EdgeIIoT-dataset.csv` (same file Galal and Dhaou audited, for direct comparability).
- **Protocol A (buggy):** official Readme Step 5 recipe exactly, random 80/20 split, no dedup.
- **Protocol B (corrected):** canonicalize placeholders (`"0"`, `"0.0"`, empty, NaN) to one sentinel before encoding; deduplicate before the train/test split; structural encoding of high-cardinality strings.
- **Metrics:** accuracy, macro-F1, precision, recall, ROC-AUC, per-class recall, plus the existing overfitting-gap check.
- **Validation:** single-column leakage audit as a sanity check; 15-fold CV under both protocols; Naive Bayes canary rerun; SHAP TreeExplainer comparison on a stratified 20K-row sample (full-scale SHAP on 157K rows is too costly).
- **Threats to validity:** single-dataset finding (mitigated by AgriEdge existing as an external check); SHAP computational cost at scale.

### Target venues (checked October 2026)
| Venue | Type | Notes |
|---|---|---|
| **IEEE Access** | Journal, rolling | Strongest fit — published the original Edge-IIoTset paper. No fixed deadline. Safest primary target. |
| **IEEE Internet of Things Journal** | Journal, rolling | Higher-impact stretch target; longer review cycle. |
| **IEEE LatinIoT 2027** | Conference | Deadline **28 Nov 2026** (conference 28–30 Apr 2027, Santiago). Tight (~6 weeks from the plan date) but achievable if Contributions #1+#2 are prioritized. |

Most other 2026 IEEE IoT-security conference CFPs had deadlines that already passed as of this writing.

### 8–10 week timeline (summary)
1. Reproduce the single-column leakage audit on the student's own data copy (now done — see §2).
2. Implement Protocol A and Protocol B preprocessing in `intrusion_detection.py`.
3. Run RF + XGBoost under Protocol A; run Naive Bayes canary under Protocol B.
4. Run RF + XGBoost under Protocol B, 15-fold CV.
5. SHAP TreeExplainer on RF and XGBoost, Protocol A vs. B.
6. (Optional) deployment-cost benchmark + rebuild `.pkl` pipeline on the corrected model.
7–8. Draft the paper (methodology, then results/discussion).
9. Internal review pass.
10. Final formatting and submission; archive the repo + dataset version used.

---

## 6. Open Decision Points

- **Venue:** tight LatinIoT 2027 deadline vs. the safer, no-deadline IEEE Access route — not yet decided by the student.
- **Code implementation:** Protocol A/B rework of `intrusion_detection.py` (adding the leakage audit, both preprocessing paths, 4-model comparison, SHAP before/after) has been scoped but not yet written — this is the next concrete step once the student confirms the venue/priority.

---

## 7. Linked Artifacts

- Full research plan (8-section, continuously updated): Claude Doc — *"Edge-IIoTset Leakage-Aware IDS — Novel Contribution Research Plan"* (https://claude.ai/code/artifact/d75d77b5-6ae9-4ded-bd46-04499ee084a1).
- `/mnt/user-data/outputs/Edge_IIoTset_RF_vs_XGBoost.ipynb` and `.py` fallback.
- `/mnt/user-data/outputs/IoT-Intrusion-Detection-Edge-IIoTset.zip` (DevOps lab repo).
- `/mnt/user-data/outputs/Related_Work_Literature_Review.md`.
- `/mnt/user-data/outputs/Research_Journey_Documentation.md` (earlier chronological journey log, includes a superseded GoBug dataset direction).
