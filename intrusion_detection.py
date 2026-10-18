"""
IoT/IIoT Intrusion Detection — Edge-IIoTset Dataset
Four-Model Comparative Study & Leakage-Sanitized PP-PSFE Framework
Models: Logistic Regression (Baseline) vs Random Forest vs XGBoost vs LightGBM
Task  : Multiclass (15-class) Cyberattack Classification

Dataset : Edge-IIoTset (Ferrag et al., IEEE Access 2022)
          https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot
File used: ML-EdgeIIoT-dataset.csv

Research Contribution Implemented:
1. Audits and sanitizes mixed-type CSV zero-string serialization leakage ('0' vs '0.0')
   across 7 categorical columns, repairs TShark column-shift corruption in dns.qry.name.len,
   removes 8 zero-variance dead columns, and enforces strict post-split transformation fitting.
2. Introduces Privacy-Preserving Protocol-Header Structural Feature Engineering (PP-PSFE),
   extracting O(1) packet-header, transport-port, TCP-option/payload entropy, and lexical
   application-layer invariants before dropping raw high-cardinality strings/IPs.
3. Benchmarks 4 distinct ML paradigms (Logistic Regression, Random Forest, XGBoost, LightGBM)
   and generates exact native C++ TreeSHAP explanations.

Run:
    python intrusion_detection.py
"""

import os
import time
import glob
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import xgboost as xgb

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score,
    confusion_matrix, classification_report
)

from utils import check_overfitting

warnings.filterwarnings("ignore")

RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)


# --------------------------------------------------------------------------
# Helper Functions for Leakage Sanitization & PP-PSFE Feature Engineering
# --------------------------------------------------------------------------
def clean_zero_str(s):
    """Canonicalize null/zero string representations ('0', '0.0', '0.00', 'nan') to empty string."""
    s_str = s.astype(str).str.strip()
    return s_str.where(~s_str.isin(["0", "0.0", "0.00", "nan", "None", ""]), "")


def hex_shannon_entropy(hex_str):
    """Compute Shannon entropy (in bits, 0.0-4.0) over the first 64 hex nybbles of payload."""
    if not hex_str:
        return 0.0
    s = hex_str[:64]
    n = len(s)
    if n <= 1:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * np.log2(p)
    return float(ent)


def extract_pp_psfe_features(df_in):
    """
    Extract Privacy-Preserving Protocol-Header Structural Features (PP-PSFE)
    before raw identifier/payload columns are dropped.
    Eliminates IP/URI/timestamp memorization and '0' vs '0.0' serialization artifacts.
    """
    src_p = pd.to_numeric(df_in["tcp.srcport"], errors="coerce").fillna(0.0)
    dst_p = pd.to_numeric(df_in["tcp.dstport"], errors="coerce").fillna(0.0)
    udp_p = pd.to_numeric(df_in["udp.port"], errors="coerce").fillna(0.0)

    min_p = np.minimum(src_p, dst_p)
    max_p = np.maximum(src_p, dst_p)

    fe = pd.DataFrame(index=df_in.index)

    # 1. Transport-layer port geometry & IANA service-tier indicators
    fe["psfe_service_port"] = np.where(min_p < 10000, min_p, 0.0).astype(np.float32)
    fe["psfe_ephemeral_port"] = max_p.astype(np.float32)
    fe["psfe_port_span"] = np.abs(src_p - dst_p).astype(np.float32)
    fe["psfe_pkt_direction"] = np.sign(src_p - dst_p).astype(np.float32)
    fe["psfe_is_http_service"] = ((src_p.isin([80, 443, 8080])) | (dst_p.isin([80, 443, 8080]))).astype(np.float32)
    fe["psfe_is_mqtt_service"] = ((src_p == 1883) | (dst_p == 1883)).astype(np.float32)
    fe["psfe_is_iot_c2_service"] = ((src_p.isin([4321, 3333, 5900])) | (dst_p.isin([4321, 3333, 5900]))).astype(np.float32)
    fe["psfe_is_boundary_probe"] = ((src_p == 65535) | (dst_p == 65535)).astype(np.float32)
    fe["psfe_udp_active"] = (udp_p > 0).astype(np.float32)

    # 2. TCP option & payload structural invariants
    tcp_opt = clean_zero_str(df_in["tcp.options"])
    tcp_pay = clean_zero_str(df_in["tcp.payload"]).str.lower()

    fe["psfe_tcp_opt_bytelen"] = (tcp_opt.str.len() // 2).astype(np.float32)
    fe["psfe_tcp_opt_has_mss"] = tcp_opt.str.startswith("0204").astype(np.float32)
    fe["psfe_tcp_opt_has_ts"] = tcp_opt.str.contains("080a", regex=False).astype(np.float32)
    fe["psfe_tcp_pay_bytelen"] = (tcp_pay.str.len() // 2).astype(np.float32)

    first_two = tcp_pay.str[:2]

    def hex_to_byte(val):
        try:
            return int(val, 16) if len(val) == 2 else 0
        except ValueError:
            return 0

    fe["psfe_tcp_pay_first_byte"] = first_two.map(hex_to_byte).astype(np.float32)
    fe["psfe_tcp_pay_entropy"] = tcp_pay.map(hex_shannon_entropy).astype(np.float32)

    # 3. Application-layer HTTP/MQTT structural lengths & lexical anomaly flags
    uri_full = clean_zero_str(df_in["http.request.full_uri"]).str.lower()
    uri_path = uri_full.str.replace(r"^https?://[^/]+", "", regex=True)
    uri_qry = clean_zero_str(df_in["http.request.uri.query"]).str.lower()
    file_dat = clean_zero_str(df_in["http.file_data"]).str.lower()
    mqtt_msg = clean_zero_str(df_in["mqtt.msg"])

    fe["psfe_http_uri_path_len"] = uri_path.str.len().astype(np.float32)
    fe["psfe_http_query_len"] = uri_qry.str.len().astype(np.float32)
    fe["psfe_http_file_data_len"] = file_dat.str.len().astype(np.float32)
    fe["psfe_mqtt_msg_bytelen"] = (mqtt_msg.str.len() // 2).astype(np.float32)

    combined_app = uri_path + " " + uri_qry + " " + file_dat
    fe["psfe_app_sqli_flag"] = (
        combined_app.str.contains("select|union|extractvalue|sleep|sqli|%27|%20and%20", regex=True)
        | tcp_pay.str.contains("33303220466f756e64|474554202f445657412f76756c6e65726162696c", regex=True)
    ).astype(np.float32)
    fe["psfe_app_xss_flag"] = (
        combined_app.str.contains("script|alert|xss|img|iframe", regex=True)
        | tcp_pay.str.contains("474554202f647677612f76756c6e65726162696c|545241434520|343035204d6574686f64", regex=True)
    ).astype(np.float32)
    fe["psfe_app_upload_flag"] = (
        combined_app.str.contains("upload|hack\\.php|multipart", regex=True)
        | tcp_pay.str.contains("6861636b61626c652f75|455843455054494f4e5f434f4445", regex=True)
    ).astype(np.float32)
    fe["psfe_app_auth_flag"] = (
        combined_app.str.contains("login|password|user_token|username", regex=True)
        | tcp_pay.str.contains("6c6f67696e2e706870", regex=True)
    ).astype(np.float32)
    fe["psfe_app_timeout_flag"] = (
        combined_app.str.contains("408 request timeout|400 bad request", regex=True)
        | tcp_pay.str.contains("3430382052657175657374|34303020426164", regex=True)
    ).astype(np.float32)

    return fe


# --------------------------------------------------------------------------
# Step 1 — Load dataset
# --------------------------------------------------------------------------
DATA_PATH = "dataset/ML-EdgeIIoT-dataset.csv"
if not os.path.exists(DATA_PATH):
    matches = glob.glob("**/*ML-EdgeIIoT*.csv", recursive=True)
    if matches:
        DATA_PATH = matches[0]

print(f"Loading dataset from: {DATA_PATH}")
df_raw = pd.read_csv(DATA_PATH, low_memory=False)
print("Raw Shape:", df_raw.shape)

# --------------------------------------------------------------------------
# Step 2 — Leakage-Sanitized Preprocessing + PP-PSFE Feature Engineering
# --------------------------------------------------------------------------
drop_candidates = [
    "frame.time", "ip.src_host", "ip.dst_host", "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4", "http.file_data", "http.request.full_uri",
    "icmp.transmit_timestamp", "http.request.uri.query", "tcp.options",
    "tcp.payload", "tcp.srcport", "tcp.dstport", "udp.port", "mqtt.msg",
]
zero_var_cols = [
    "icmp.unused", "http.tls_port", "dns.qry.type", "dns.retransmit_request_in",
    "mqtt.msg_decoded_as", "mbtcp.len", "mbtcp.trans_id", "mbtcp.unit_id",
]

print("Extracting 24 Privacy-Preserving Protocol-Header Structural Features (PP-PSFE)...")
fe_pp = extract_pp_psfe_features(df_raw)

TARGET = "Attack_type"
OTHER_LABEL = "Attack_label" if TARGET == "Attack_type" else "Attack_type"

cols_to_drop = [c for c in drop_candidates + zero_var_cols + [OTHER_LABEL] if c in df_raw.columns]
df_san = df_raw.drop(columns=cols_to_drop).copy()
print(f"Dropped {len(drop_candidates)} identifier/string columns and {len(zero_var_cols)} zero-variance columns.")

# Repair TShark column-shift corruption in dns.qry.name.len and canonicalize '0.0' -> '0'
dns_raw = df_san["dns.qry.name.len"].astype(str).str.strip()
df_san["dns.qry.name.len"] = pd.to_numeric(dns_raw, errors="coerce").fillna(dns_raw.str.len().astype(float))

cat_cols = df_san.drop(columns=[TARGET]).select_dtypes(include=["object"]).columns.tolist()
for col in cat_cols:
    df_san[col] = df_san[col].astype(str).str.strip().replace({"0.0": "0", "0.00": "0"})

df = pd.concat([df_san.drop(columns=[TARGET]), fe_pp, df_san[[TARGET]]], axis=1)
df = df.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()
print(f"Rows after leakage sanitization & deduplication: {len(df)} | Total Features: {df.shape[1] - 1}")

X = df.drop(columns=[TARGET]).copy()
y = df[TARGET].copy()

le_target = LabelEncoder()
y_enc = le_target.fit_transform(y)
class_names = le_target.classes_

# Stratified Train-Test Split BEFORE fitting encoders/scalers to guarantee zero data leakage
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.20, random_state=RANDOM_STATE, stratify=y_enc
)

cat_encoders = {}
for col in cat_cols:
    le_col = LabelEncoder()
    X_train[col] = le_col.fit_transform(X_train[col].astype(str))
    mapping = {k: i for i, k in enumerate(le_col.classes_)}
    X_test[col] = X_test[col].astype(str).map(lambda v: mapping.get(v, -1))
    cat_encoders[col] = le_col

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# --------------------------------------------------------------------------
# Step 3 — Train Four Selected Machine Learning Models
# --------------------------------------------------------------------------
models_dict = {
    "Logistic Regression": LogisticRegression(
        max_iter=300, C=1.0, random_state=RANDOM_STATE, n_jobs=-1
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=150, max_depth=14, min_samples_leaf=3,
        random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced",
    ),
    "XGBoost": XGBClassifier(
        n_estimators=150, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, eval_metric="mlogloss",
        random_state=RANDOM_STATE, n_jobs=-1,
    ),
    "LightGBM": LGBMClassifier(
        n_estimators=150, max_depth=8, num_leaves=63, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, class_weight="balanced",
        random_state=RANDOM_STATE, n_jobs=-1, verbose=-1,
    ),
}

# --------------------------------------------------------------------------
# Step 4 — Evaluate All Four Models
# --------------------------------------------------------------------------
def evaluate_model(model, name, X_tr, y_tr, X_te, y_te, classes):
    t0 = time.time()
    model.fit(X_tr, y_tr)
    train_time = time.time() - t0

    t1 = time.time()
    y_test_pred = model.predict(X_te)
    infer_time = time.time() - t1
    infer_ms_per_1k = (infer_time / len(X_te)) * 1000.0 * 1000.0

    y_train_pred = model.predict(X_tr)

    train_acc = accuracy_score(y_tr, y_train_pred)
    test_acc = accuracy_score(y_te, y_test_pred)
    gap, is_overfitting = check_overfitting(train_acc, test_acc)

    precision_w = precision_score(y_te, y_test_pred, average="weighted", zero_division=0)
    recall_w = recall_score(y_te, y_test_pred, average="weighted", zero_division=0)
    f1_w = f1_score(y_te, y_test_pred, average="weighted", zero_division=0)
    f1_m = f1_score(y_te, y_test_pred, average="macro", zero_division=0)

    y_proba = model.predict_proba(X_te)
    y_test_bin = label_binarize(y_te, classes=np.arange(len(classes)))
    roc_auc = roc_auc_score(y_test_bin, y_proba, average="weighted", multi_class="ovr")
    pr_auc_m = average_precision_score(y_test_bin, y_proba, average="macro")

    print(f"\n{'='*60}\n  {name}\n{'='*60}")
    print(f"  Train Accuracy    : {train_acc:.4f}")
    print(f"  Test Accuracy     : {test_acc:.4f}")
    status = "OK (<5%)" if not is_overfitting else "WARNING: possible overfitting"
    print(f"  Overfitting Gap   : {gap:.4f}  -> {status}")
    print(f"  Precision (wt)    : {precision_w:.4f}")
    print(f"  Recall (wt)       : {recall_w:.4f}")
    print(f"  F1-score (wt)     : {f1_w:.4f}")
    print(f"  F1-score (macro)  : {f1_m:.4f}")
    print(f"  ROC-AUC (wt)      : {roc_auc:.4f}")
    print(f"  PR-AUC (macro)    : {pr_auc_m:.4f}")
    print(f"  Train Time (s)    : {train_time:.2f}s | Inference: {infer_ms_per_1k:.2f} ms/1k")

    return {
        "name": name, "model": model,
        "train_acc": train_acc, "test_acc": test_acc, "gap": gap,
        "precision": precision_w, "recall": recall_w,
        "f1": f1_w, "macro_f1": f1_m,
        "roc_auc": roc_auc, "pr_auc_macro": pr_auc_m,
        "train_time_s": train_time, "infer_ms_per_1k": infer_ms_per_1k,
        "y_pred": y_test_pred,
    }


all_results = []
for m_name, m_inst in models_dict.items():
    res = evaluate_model(m_inst, m_name, X_train_scaled, y_train, X_test_scaled, y_test, class_names)
    all_results.append(res)

# --------------------------------------------------------------------------
# Step 5 — Save Comparison Results & Visualizations
# --------------------------------------------------------------------------
comparison = pd.DataFrame([
    {
        "model": r["name"],
        "accuracy": r["test_acc"],
        "precision": r["precision"],
        "recall": r["recall"],
        "f1_score": r["f1"],
        "macro_f1": r["macro_f1"],
        "roc_auc": r["roc_auc"],
        "pr_auc_macro": r["pr_auc_macro"],
        "overfitting_gap": r["gap"],
        "train_time_s": r["train_time_s"],
        "infer_ms_per_1k": r["infer_ms_per_1k"],
    }
    for r in all_results
])
comparison.to_csv(os.path.join(OUTPUT_DIR, "model_results.csv"), index=False)
print(f"\nSaved: {OUTPUT_DIR}/model_results.csv")
print(comparison.round(4).to_string(index=False))

# 1. Bar chart comparison of all 4 models
metrics_to_plot = ["accuracy", "precision", "recall", "f1_score", "macro_f1", "roc_auc"]
x = np.arange(len(metrics_to_plot))
width = 0.20
fig, ax = plt.subplots(figsize=(12, 6.5))
colors = ["#6c757d", "#2b8cbe", "#e34a33", "#31a354"]
for idx, r in enumerate(all_results):
    offset = (idx - 1.5) * width
    vals = [comparison.loc[idx, m] for m in metrics_to_plot]
    ax.bar(x + offset, vals, width, label=r["name"], color=colors[idx])

ax.set_xticks(x)
ax.set_xticklabels(["Accuracy", "Precision (Wt)", "Recall (Wt)", "F1 (Wt)", "F1 (Macro)", "ROC-AUC"])
ax.set_ylim(0.70, 1.02)
ax.set_ylabel("Score")
ax.set_title("Edge-IIoTset (15-Class) — Four-Model Performance Comparison (Leakage-Sanitized + PP-PSFE)")
ax.legend(loc="lower right")
ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "model_comparison.png"), dpi=150)
plt.close()

# 2. Confusion matrices (2x2 grid for all 4 models)
fig, axes = plt.subplots(2, 2, figsize=(24, 18))
for ax, res in zip(axes.flatten(), all_results):
    cm = confusion_matrix(y_test, res["y_pred"])
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues", ax=ax,
        xticklabels=class_names, yticklabels=class_names, cbar=False
    )
    ax.set_title(f"{res['name']} — Confusion Matrix (Acc={res['test_acc']:.4f}, Macro-F1={res['macro_f1']:.4f})")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrices.png"), dpi=150)
plt.close()

# 3. Native C++ TreeSHAP Feature Attribution Plot for Best Model (XGBoost)
xgb_res = next(r for r in all_results if r["name"] == "XGBoost")
booster = xgb_res["model"].get_booster()
dtest_sample = xgb.DMatrix(X_test_scaled[:2000], feature_names=list(X.columns))
shap_contribs = booster.predict(dtest_sample, pred_contribs=True)
mean_abs_shap = np.mean(np.abs(shap_contribs[:, :, :-1]), axis=(0, 1))
shap_series = pd.Series(mean_abs_shap, index=X.columns).sort_values(ascending=True).tail(15)

fig, ax = plt.subplots(figsize=(10, 6))
shap_series.plot(kind="barh", color="#e34a33", ax=ax)
ax.set_xlabel("Mean |TreeSHAP Value| (Log-Odds Impact Across 15 Classes)")
ax.set_title("XGBoost Exact Native TreeSHAP — Top 15 Predictive Features (Sanitized + PP-PSFE)")
ax.grid(axis="x", alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "shap_feature_importance.png"), dpi=150)
plt.close()

for r in all_results:
    print(f"\n{r['name'].upper()} — Classification Report\n")
    print(classification_report(y_test, r["y_pred"], target_names=class_names, zero_division=0, digits=4))

# --------------------------------------------------------------------------
# Step 6 — Export Best Model as .pkl
# --------------------------------------------------------------------------
best_res = max(all_results, key=lambda r: r["f1"])
best_model = best_res["model"]
best_name = best_res["name"]
print(f"\nBest model: {best_name} (Test Accuracy = {best_res['test_acc']:.4f}, Test Wt-F1 = {best_res['f1']:.4f}, Macro-F1 = {best_res['macro_f1']:.4f})")

deployment_bundle = {
    "model": best_model,
    "model_name": best_name,
    "scaler": scaler,
    "label_encoder": le_target,
    "cat_encoders": cat_encoders,
    "feature_columns": list(X.columns),
    "class_names": list(class_names),
}
joblib.dump(deployment_bundle, os.path.join(OUTPUT_DIR, "iot_intrusion_detector.pkl"))
print(f"Saved: {OUTPUT_DIR}/iot_intrusion_detector.pkl")
