# Stage 15.4 — Troubleshooting Evidence Log

## Incident 1: Windows Socket Access Permission Error on Port 5000 (Stage 6.3)
- **Command Executed:**
  ```powershell
  python backend\app.py
  ```
- **Current Working Directory (`pwd`):**
  `D:\Semester 7\DEVOPS Lab\IoT-Intrusion-Detection-Edge-IIoTset\IoT-Intrusion-Detection-Edge-IIoTset`
- **Actual Error Output:**
  ```text
   * Serving Flask app 'app'
   * Debug mode: off
  An attempt was made to access a socket in a way forbidden by its access permissions
  ```
- **Diagnostic Commands & Root Cause:**
  Running `netsh interface ipv4 show excludedportrange protocol=tcp` and `netstat -ano | Select-String ":5000"` revealed:
  ```text
  Protocol tcp Port Exclusion Ranges
  Start Port    End Port
  ----------    --------
        5000        5000

  TCP    0.0.0.0:5000     0.0.0.0:0    LISTENING    4
  TCP    127.0.0.1:5000   0.0.0.0:0    LISTENING    4
  ```
  On this Windows host, TCP port `5000` is reserved in the OS excluded port range and actively bound by PID `4` (`NT Kernel & System` / `HTTP.sys`).
- **Expected Output:**
  `Running on http://127.0.0.1:<port>` with HTTP 200 responses on `/health` and `/predict`.
- **Correction Applied (per Stage 6.5 & Troubleshooting Table "port 5000 unavailable"):**
  Updated `backend/app.py`, `backend/test_api.py`, and `frontend/proxy.conf.json` to bind and proxy local Flask traffic via `http://127.0.0.1:5050` (`PORT=5050`).

---

## Incident 2: Mixed-Type String/Integer Category Coercion in `sample_inputs.csv` (Stage 5.4)
- **Command Executed:**
  ```powershell
  python backend\test_pipeline.py
  ```
- **Current Working Directory (`pwd`):**
  `D:\Semester 7\DEVOPS Lab\IoT-Intrusion-Detection-Edge-IIoTset\IoT-Intrusion-Detection-Edge-IIoTset`
- **Actual Error Output:**
  `TypeError: ufunc 'isnan' not supported for the input types` inside `OrdinalEncoder._transform`.
- **Root Cause:**
  When `pd.read_csv("data/sample_inputs.csv", nrows=1)` read row 0, categorical columns containing `"0"` (such as `http.request.method`) were parsed by Pandas as integer `0` (`int64`), whereas `OrdinalEncoder` was fitted on string categories (`'0'`, `'GET'`, `'POST'`).
- **Correction Applied:**
  Wrapped each categorical column inside `backend/package_existing.py` with `Pipeline([("to_str", FunctionTransformer(np.asarray, kw_args={"dtype": str})), ("ord", OrdinalEncoder(...))])` and removed `feature_names_in_` on `StandardScaler`, ensuring both integer `0` (from CSV) and string `"0"` (from Angular JSON) transform identically with zero warnings.

---

## Incident 3: GitHub Actions Unpickling Version Mismatch (`scikit-learn` 1.6.0 vs 1.9.1) & Pages Enablement (Stages 13 & 14)
- **Command Executed (in GitHub Actions `ubuntu-latest` runner):**
  ```bash
  python -m pytest -q backend/tests/test_api.py
  ```
- **Actual Error Output:**
  ```text
  InconsistentVersionWarning: Trying to unpickle estimator Pipeline from version 1.6.0 when using version 1.9.1.
  AttributeError: Can't get attribute '_RemainderColsList' on <module 'sklearn.compose._column_transformer'>
  ```
  And in `Deploy Angular to GitHub Pages`:
  ```text
  Get Pages site failed. Please verify that the repository has Pages enabled and configured to build using GitHub Actions, or consider exploring the `enablement` parameter for this action.
  ```
- **Root Cause:**
  1. Using `scikit-learn>=1.6.0` in `backend/requirements.txt` caused `pip` on `ubuntu-latest` to install `scikit-learn==1.9.1`, where internal class `_RemainderColsList` in `sklearn.compose._column_transformer` was removed.
  2. GitHub Pages had not yet been enabled on the new repository.
- **Correction Applied:**
  1. Pinned exact serialization-matching versions (`scikit-learn==1.6.0`, `pandas==2.2.3`, `numpy==2.2.1`, `xgboost==3.2.0`, `joblib==1.4.2`) in `backend/requirements.txt`.
  2. Added `with: enablement: true` to `actions/configure-pages@v5` in `.github/workflows/pages.yml`.

