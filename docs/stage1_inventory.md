# Stage 1 — Project Plan, Provenance, and Model Inventory

## 1.1 Model Provenance
- **Project Name:** IoT/IIoT Intrusion Detection — Leakage-Sanitized PP-PSFE Full-Stack Research Application
- **Problem Type:** 15-Class Multiclass Cyberattack Classification (`classification`)
- **Dataset:** Edge-IIoTset (`ML-EdgeIIoT-dataset.csv`, Ferrag et al., *IEEE Access*, 2022, DOI: `10.1109/ACCESS.2022.3165809`)
- **Training Script:** `intrusion_detection.py`
- **Selected Best Model:** `XGBClassifier` (`n_estimators=150`, `max_depth=6`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8`, `eval_metric="mlogloss"`, `random_state=42`)
- **Measured Performance (Held-Out Test Set, N=30,478):**
  - Test Accuracy: `96.49%`
  - Weighted Precision / Recall / F1-Score: `0.9663` / `0.9649` / `0.9649`
  - Macro F1-Score: `0.9618`
  - Weighted ROC-AUC: `0.9991` | Macro PR-AUC: `0.9874`
  - Overfitting Gap: `0.0057` (`0.57%`, well below `5%` threshold)
- **Target Classes (15):**
  `['Backdoor', 'DDoS_HTTP', 'DDoS_ICMP', 'DDoS_TCP', 'DDoS_UDP', 'Fingerprinting', 'MITM', 'Normal', 'Password', 'Port_Scanning', 'Ransomware', 'SQL_injection', 'Uploading', 'Vulnerability_scanner', 'XSS']`
- **Python & Library Environment:** Python `3.12.10`, `scikit-learn==1.6.0`, `xgboost==3.2.0`, `pandas==2.2.3`, `numpy==2.2.1`, `joblib==1.4.2`

## 1.2 Saved Artifact & Preprocessing Architecture
- **Source Artifact:** `output/iot_intrusion_detector.pkl`
- **Packaged Deployment Bundle:** `backend/models/model_bundle.joblib`
- **Pipeline Steps:** Standard fitted `sklearn.pipeline.Pipeline` comprising:
  1. `ColumnTransformer`: applies fitted `OrdinalEncoder` (preserving exact training category order for the 6 categorical protocol fields: `http.request.method`, `http.referer`, `http.request.version`, `mqtt.conack.flags`, `mqtt.protoname`, `mqtt.topic`) and passes through the 56 numerical features in exact column order.
  2. `StandardScaler`: applies the exact training mean and variance scaling across all 62 features.
  3. `XGBClassifier`: outputs the predicted class index (`0..14`) and 15-class probability vector.

## 1.3 Input Feature Schema (62 Features)
- **38 Sanitized Core Protocol Features:**
  `arp.opcode`, `arp.hw.size`, `icmp.checksum`, `icmp.seq_le`, `http.content_length`, `http.request.method` (category), `http.referer` (category), `http.request.version` (category), `http.response`, `tcp.ack`, `tcp.ack_raw`, `tcp.checksum`, `tcp.connection.fin`, `tcp.connection.rst`, `tcp.connection.syn`, `tcp.connection.synack`, `tcp.flags`, `tcp.flags.ack`, `tcp.len`, `tcp.seq`, `udp.stream`, `udp.time_delta`, `dns.qry.name`, `dns.qry.name.len`, `dns.qry.qu`, `dns.retransmission`, `dns.retransmit_request`, `mqtt.conack.flags` (category), `mqtt.conflag.cleansess`, `mqtt.conflags`, `mqtt.hdrflags`, `mqtt.len`, `mqtt.msgtype`, `mqtt.proto_len`, `mqtt.protoname` (category), `mqtt.topic` (category), `mqtt.topic_len`, `mqtt.ver`
- **24 PP-PSFE Engineered Structural Features:**
  `psfe_service_port`, `psfe_ephemeral_port`, `psfe_port_span`, `psfe_pkt_direction`, `psfe_is_http_service`, `psfe_is_mqtt_service`, `psfe_is_iot_c2_service`, `psfe_is_boundary_probe`, `psfe_udp_active`, `psfe_tcp_opt_bytelen`, `psfe_tcp_opt_has_mss`, `psfe_tcp_opt_has_ts`, `psfe_tcp_pay_bytelen`, `psfe_tcp_pay_first_byte`, `psfe_tcp_pay_entropy`, `psfe_http_uri_path_len`, `psfe_http_query_len`, `psfe_http_file_data_len`, `psfe_mqtt_msg_bytelen`, `psfe_app_sqli_flag`, `psfe_app_xss_flag`, `psfe_app_upload_flag`, `psfe_app_auth_flag`, `psfe_app_timeout_flag`

## 1.4 Deployment Scope Boundary
- **Local Execution:** Flask REST API (`http://127.0.0.1:5000`) executes live model inference; Angular dev server (`http://localhost:4200`) proxies `/api/predict` to Flask.
- **GitHub Pages:** Hosts only the static compiled Angular 22 browser bundle; live prediction is automatically disabled on non-local hostnames with a clear user notice.
