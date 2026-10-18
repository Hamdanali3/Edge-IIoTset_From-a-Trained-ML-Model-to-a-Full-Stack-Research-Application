# IoT/IIoT Intrusion Detection — Full-Stack Research Application (Edge-IIoTset)

## 1. Project Overview & Research Provenance
This repository contains both the **4-Model Machine Learning Research Pipeline** ([`intrusion_detection.py`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/intrusion_detection.py)) and the **15-Stage Full-Stack Research Application** (**Flask REST API** + **Angular 22 Standalone Frontend** + **GitHub Actions CI/CD** + **GitHub Pages Static Deployment**) for 15-class cyberattack classification on the **Edge-IIoTset** benchmark ([Ferrag et al., *IEEE Access*, 2022](https://doi.org/10.1109/ACCESS.2022.3165809)).

### Trusted Model Provenance (Stage 1.1 & Stage 1.2)
- **Problem Type:** 15-Class Multiclass Classification (`task: "classification"`)
- **Target Classes (15):** `Backdoor`, `DDoS_HTTP`, `DDoS_ICMP`, `DDoS_TCP`, `DDoS_UDP`, `Fingerprinting`, `MITM`, `Normal`, `Password`, `Port_Scanning`, `Ransomware`, `SQL_injection`, `Uploading`, `Vulnerability_scanner`, `XSS`
- **Training Script:** [`intrusion_detection.py`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/intrusion_detection.py)
- **Packaged Artifact:** [`backend/models/model_bundle.joblib`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/backend/models/model_bundle.joblib) (packaged via [`backend/package_existing.py`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/backend/package_existing.py))
- **Pipeline Architecture:** Self-contained fitted `sklearn.pipeline.Pipeline` combining:
  1. `ColumnTransformer` with string-safe `OrdinalEncoder`s for the 6 categorical protocol fields (`http.request.method`, `http.referer`, `http.request.version`, `mqtt.conack.flags`, `mqtt.protoname`, `mqtt.topic`) and numeric passthrough for the 56 numerical fields in exact column order.
  2. `StandardScaler` fitted strictly on the training split.
  3. `XGBClassifier` (`n_estimators=150`, `max_depth=6`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8`).

---

## 2. Four-Model Research Benchmark Results (Leakage-Sanitized + PP-PSFE Framework)

| Model | Test Accuracy | Precision (Wt) | Recall (Wt) | F1-Score (Wt) | Macro F1-Score | ROC-AUC (Wt) | PR-AUC (Macro) | Overfitting Gap | Train Time (s) | Inference (ms/1k) |
|---|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression (Baseline) | 84.87% | 0.8736 | 0.8487 | 0.8479 | 0.8419 | 0.9829 | 0.8656 | +0.0016 | 23.18s | 0.43 ms |
| Random Forest | 94.38% | 0.9455 | 0.9438 | 0.9438 | 0.9414 | 0.9978 | 0.9768 | +0.0020 | 3.46s | 10.35 ms |
| LightGBM | 96.33% | 0.9640 | 0.9633 | 0.9632 | 0.9596 | 0.9991 | 0.9888 | +0.0210 | 7.61s | 18.35 ms |
| **XGBoost (Selected Best)** | **96.49%** | **0.9663** | **0.9649** | **0.9649** | **0.9618** | **0.9991** | **0.9874** | **+0.0057** | **13.93s** | **3.54 ms** |

---

## 3. Input Feature Schema (62 Features)
The model accepts **62 input features** defined in [`frontend/src/app/feature-schema.ts`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/frontend/src/app/feature-schema.ts), [`data/sample_inputs.csv`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/data/sample_inputs.csv), and [`backend/test_payload.json`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/backend/test_payload.json):
- **38 Sanitized Core Protocol Features:** ARP (`arp.opcode`, `arp.hw.size`), ICMP (`icmp.checksum`, `icmp.seq_le`), HTTP (`http.content_length`, `http.request.method`, `http.referer`, `http.request.version`, `http.response`), TCP (`tcp.ack`, `tcp.ack_raw`, `tcp.checksum`, `tcp.connection.fin`, `tcp.connection.rst`, `tcp.connection.syn`, `tcp.connection.synack`, `tcp.flags`, `tcp.flags.ack`, `tcp.len`, `tcp.seq`), UDP/DNS (`udp.stream`, `udp.time_delta`, `dns.qry.name`, `dns.qry.name.len`, `dns.qry.qu`, `dns.retransmission`, `dns.retransmit_request`), and MQTT (`mqtt.conack.flags`, `mqtt.conflag.cleansess`, `mqtt.conflags`, `mqtt.hdrflags`, `mqtt.len`, `mqtt.msgtype`, `mqtt.proto_len`, `mqtt.protoname`, `mqtt.topic`, `mqtt.topic_len`, `mqtt.ver`).
- **24 PP-PSFE Engineered Structural Features:** Transport service/port geometry (`psfe_service_port`, `psfe_ephemeral_port`, `psfe_port_span`, `psfe_pkt_direction`, `psfe_is_http_service`, `psfe_is_mqtt_service`, `psfe_is_iot_c2_service`, `psfe_is_boundary_probe`, `psfe_udp_active`), TCP header/payload structure (`psfe_tcp_opt_bytelen`, `psfe_tcp_opt_has_mss`, `psfe_tcp_opt_has_ts`, `psfe_tcp_pay_bytelen`, `psfe_tcp_pay_first_byte`, `psfe_tcp_pay_entropy`), and application-layer lengths/flags (`psfe_http_uri_path_len`, `psfe_http_query_len`, `psfe_http_file_data_len`, `psfe_mqtt_msg_bytelen`, `psfe_app_sqli_flag`, `psfe_app_xss_flag`, `psfe_app_upload_flag`, `psfe_app_auth_flag`, `psfe_app_timeout_flag`).

---

## 4. Verified Environment & Software Versions
Recorded in [`docs/environment.txt`](file:///d:/Semester%207/DEVOPS%20Lab/IoT-Intrusion-Detection-Edge-IIoTset/IoT-Intrusion-Detection-Edge-IIoTset/docs/environment.txt):
- **OS:** Windows
- **Python:** `3.12.10` (`flask==3.1.0`, `scikit-learn==1.6.0`, `xgboost==3.2.0`, `lightgbm==4.7.0`, `pandas==2.2.3`, `numpy==2.2.1`, `joblib==1.4.2`, `pytest==8.3.4`, `requests==2.32.3`)
- **Node.js / npm:** `v24.16.0` / `11.13.0`
- **Angular CLI:** `22.2.3`
- **Git:** `2.54.0.windows.1`

---

## 5. Project Structure
```text
IoT-Intrusion-Detection-Edge-IIoTset/
├── .gitignore
├── README.md
├── intrusion_detection.py          # 4-Model training + PP-PSFE + TreeSHAP script
├── utils.py                        # Overfitting-check & score normalization helpers
├── requirements.txt
├── backend/
│   ├── app.py                      # Flask REST API (GET /health, POST /predict)
│   ├── requirements.txt            # Backend CI/runtime dependencies
│   ├── package_existing.py         # Packages fitted Pipeline into model_bundle.joblib
│   ├── make_payload.py             # Generates test_payload.json from sample_inputs.csv
│   ├── test_pipeline.py            # Direct pipeline inference verification
│   ├── test_payload.json           # Representative 62-feature sample JSON payload
│   ├── test_api.py                 # Live HTTP client test (requests.Session)
│   ├── models/
│   │   └── model_bundle.joblib     # Fitted sklearn Pipeline + metadata
│   └── tests/
│       ├── test_api.py             # 4 positive & negative pytest API tests
│       └── test_structure.py       # Portable repository smoke test
├── data/
│   └── sample_inputs.csv           # Non-sensitive 62-feature test records
├── docs/
│   ├── environment.txt             # Verified tool versions
│   ├── stage1_inventory.md         # Model provenance & schema inventory
│   └── troubleshooting_evidence.md # Stage 15.4 verified debugging & remediation log
├── frontend/                       # Angular 22 standalone application
│   ├── proxy.conf.json             # Dev proxy (/api -> http://127.0.0.1:5050)
│   ├── angular.json
│   ├── package.json
│   └── src/app/
│       ├── feature-schema.ts       # 62-feature definitions & 1-click sample presets
│       ├── prediction.service.ts   # HttpClient service calling /api/predict
│       ├── app.config.ts           # ApplicationConfig with provideHttpClient()
│       └── app.ts / app.html / app.css
└── .github/workflows/
    ├── ci.yml                      # Full-stack CI (pytest backend + Angular build)
    └── pages.yml                   # Static Angular deployment to GitHub Pages
```

---

## 6. Installation & Three-Terminal Startup Guide

### Step 1: Install Backend & Frontend Dependencies
```powershell
python -m pip install -r backend\requirements.txt
cd frontend
npm ci
cd ..
```

### Step 2: Terminal 1 — Start Flask REST API (Keep Open)
```powershell
python backend\app.py
```
*Verifies on `http://127.0.0.1:5050/health` (port `5050` is used by default because Windows `HTTP.sys` Kernel PID 4 reserves port `5000`; configurable via `$env:PORT`).*

### Step 3: Terminal 2 — Start Angular 22 Dev Server with Proxy (Keep Open)
```powershell
cd frontend
npx ng serve --open --proxy-config proxy.conf.json
```
*Opens `http://localhost:4200` and forwards `/api/*` requests to `http://127.0.0.1:5050/*`.*

### Step 4: Terminal 3 — Run Direct Inference, Live API, and Automated Tests
```powershell
# 1. Verify direct pipeline inference without HTTP
python backend\make_payload.py
python backend\test_pipeline.py

# 2. Verify live Flask API and Angular dev proxy
curl.exe --noproxy "*" -i http://127.0.0.1:5050/health
python backend\test_api.py
curl.exe --noproxy "*" -i http://localhost:4200/api/health

# 3. Run automated pytest and unittest suites
python -m pytest -q backend\tests
python -m unittest discover -s tests -v
```

---

## 7. Deployment Scope & Research Ethics Disclaimer
- **Local vs. GitHub Pages Boundary:** The Flask backend and `model_bundle.joblib` execute locally on `127.0.0.1:5050` (and in GitHub Actions CI runners during automated `pytest` checks). **GitHub Pages hosts only the static compiled Angular 22 browser bundle** (`frontend/dist/frontend/browser`). When visited on a non-local hostname (`*.github.io`), the Angular UI automatically displays a static-demo notice and disables live prediction buttons.
- **Research & Security Disclaimer:** This software is a research and teaching prototype evaluated on the Edge-IIoTset testbed dataset. Predictions represent statistical packet/flow classifications and should be validated alongside network telemetry before automated production firewall enforcement.
