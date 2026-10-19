from pathlib import Path
import joblib
import pandas as pd
from flask import Flask, jsonify, request, send_file

BASE = Path(__file__).resolve().parent
BUNDLE = joblib.load(BASE / "models/model_bundle.joblib")
MODEL = BUNDLE["pipeline"]
FEATURES = BUNDLE["features"]
CLASS_NAMES = BUNDLE.get("class_names", [])
TASK = BUNDLE.get("task", "classification")
app = Flask(__name__)


@app.get("/")
def index():
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Edge-IIoTset Flask Inference API — Online</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1.25rem; color: #0f172a; background: #f8fafc; }}
    .card {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 10px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
    .badge {{ display: inline-block; background: #dcfce7; color: #166534; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.85rem; }}
    .btn {{ display: inline-block; margin-top: 0.75rem; background: #16a34a; color: #fff; padding: 0.6rem 1.1rem; border-radius: 8px; font-weight: 700; text-decoration: none; }}
    code {{ background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.9rem; }}
    a {{ color: #1d4ed8; font-weight: 600; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    ul {{ line-height: 1.8; }}
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">● FLASK REST API ONLINE (PORT 5050)</span>
    <h1>Edge-IIoTset 15-Class Intrusion Detection API</h1>
    <p>The trained <strong>Leakage-Sanitized + PP-PSFE XGBoost Pipeline</strong> (<code>96.49%</code> Test Accuracy, <code>0.9618</code> Macro-F1) is loaded and ready for inference.</p>
    <ul>
      <li><strong>Input Schema:</strong> <code>{len(FEATURES)}</code> features (38 sanitized protocol fields + 24 PP-PSFE structural features)</li>
      <li><strong>Target Classes ({len(CLASS_NAMES)}):</strong> <code>{", ".join(CLASS_NAMES)}</code></li>
      <li><strong>Health Check Endpoint (GET):</strong> <a href="/health"><code>http://127.0.0.1:5050/health</code></a></li>
      <li><strong>Prediction Endpoint (GET Demo / POST JSON):</strong> <a href="/predict"><code>http://127.0.0.1:5050/predict</code></a></li>
      <li><strong>Interactive Angular 22 Research Dashboard:</strong> <a href="http://localhost:4200"><code>http://localhost:4200</code></a></li>
      <li><strong>IEEE Research Paper (PDF • 450 DPI):</strong> <a href="/download-paper"><code>http://127.0.0.1:5050/download-paper</code></a></li>
    </ul>
    <a class="btn" href="/download-paper">⬇ Download IEEE Research Paper (PDF • 450 DPI)</a>
  </div>
</body>
</html>"""
    return html, 200


@app.get("/download-paper")
def download_paper():
    pdf_path = BASE.parent / "docs" / "IEEE_Research_Paper_Hamdan_Ali_233120.pdf"
    return send_file(pdf_path, as_attachment=True, download_name="IEEE_Research_Paper_Hamdan_Ali_233120.pdf")


@app.get("/health")
def health():
    return jsonify(status="ok", features=len(FEATURES), task=TASK, classes=CLASS_NAMES)


@app.get("/predict")
def predict_get_info():
    sample_csv = BASE.parent / "data" / "sample_inputs.csv"
    df_samples = pd.read_csv(sample_csv)
    preds = MODEL.predict(df_samples[FEATURES])
    probs = MODEL.predict_proba(df_samples[FEATURES])
    rows_html = ""
    scenario_names = ["Sample #1: Normal Telemetry", "Sample #2: DDoS_TCP Flood", "Sample #3: SQL_injection Exploit", "Sample #4: Ransomware C2 Flow"]
    for i in range(len(df_samples)):
        p_idx = int(preds[i])
        label = CLASS_NAMES[p_idx] if 0 <= p_idx < len(CLASS_NAMES) else str(p_idx)
        conf = float(probs[i][p_idx]) * 100.0
        badge_bg = "#dcfce7" if label == "Normal" else "#fee2e2"
        badge_fg = "#166534" if label == "Normal" else "#991b1b"
        verdict = "SAFE (NORMAL)" if label == "Normal" else f"ATTACK DETECTED: {label}"
        rows_html += f"""
        <tr>
          <td><strong>{scenario_names[i] if i < len(scenario_names) else f'Sample #{i+1}'}</strong></td>
          <td><span style="background:{badge_bg};color:{badge_fg};padding:3px 10px;border-radius:999px;font-weight:700;font-size:0.82rem;">{verdict}</span></td>
          <td><code>Class #{p_idx} ({label})</code></td>
          <td><strong>{conf:.4f}%</strong></td>
        </tr>"""
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>POST /predict Endpoint — Live Model Inference Verification</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1.25rem; color: #0f172a; background: #f8fafc; }}
    .card {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 10px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 1.25rem; }}
    .badge {{ display: inline-block; background: #dbeafe; color: #1e40af; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.82rem; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.92rem; }}
    th, td {{ padding: 0.65rem 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
    th {{ background: #f1f5f9; }}
    code {{ background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.88rem; }}
    a.btn {{ display: inline-block; margin-top: 1rem; background: #1d4ed8; color: #fff; padding: 0.6rem 1.15rem; border-radius: 8px; font-weight: 700; text-decoration: none; }}
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">● /predict ENDPOINT ACTIVE (POST JSON &amp; GET DEMO)</span>
    <h1>Edge-IIoTset XGBoost Inference Endpoint (<code>/predict</code>)</h1>
    <p>
      <strong>How this endpoint works:</strong> In normal operation, the Angular 22 frontend (<code>http://localhost:4200</code>) or API test script sends an
      <strong>HTTP POST</strong> request containing a 62-feature JSON packet to <code>http://127.0.0.1:5050/predict</code>.
      Because opening a URL in a browser address bar sends an <strong>HTTP GET</strong> request, this page automatically executes live predictions on the 4 held-out test flows from <code>data/sample_inputs.csv</code> so you can verify the model directly in your browser:
    </p>
    <table>
      <thead>
        <tr>
          <th>Test Packet Scenario</th>
          <th>Security Verdict</th>
          <th>Predicted Class</th>
          <th>XGBoost Confidence</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    <a class="btn" href="http://localhost:4200">Open Interactive Angular 22 Dashboard (http://localhost:4200) →</a>
  </div>
</body>
</html>"""
    return html, 200


@app.post("/predict")
def predict():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Expected a JSON object"), 400
    missing = [f for f in FEATURES if f not in data]
    extra = [f for f in data if f not in FEATURES]
    if missing or extra:
        return jsonify(error="Input schema mismatch",
                       missing=missing, extra=extra), 400
    frame = pd.DataFrame([[data[f] for f in FEATURES]], columns=FEATURES)
    try:
        raw_pred = MODEL.predict(frame)[0]
        pred_idx = raw_pred.item() if hasattr(raw_pred, "item") else raw_pred
        prediction_label = (
            CLASS_NAMES[int(pred_idx)]
            if isinstance(pred_idx, (int, float)) and 0 <= int(pred_idx) < len(CLASS_NAMES)
            else pred_idx
        )
        result = {
            "prediction": prediction_label,
            "predicted_class_index": pred_idx,
            "task": TASK,
            "disclaimer": "Research/teaching prototype only. Edge-IIoTset 15-class intrusion detection.",
        }
        if TASK == "classification" and hasattr(MODEL, "predict_proba"):
            probs = [round(float(p), 6) for p in MODEL.predict_proba(frame)[0].tolist()]
            result["probabilities"] = probs
            if len(CLASS_NAMES) == len(probs):
                result["class_probabilities"] = {
                    CLASS_NAMES[i]: probs[i] for i in range(len(probs))
                }
        return jsonify(result)
    except (ValueError, TypeError) as exc:
        return jsonify(error="Invalid input", detail=str(exc)), 400
    except Exception:
        app.logger.exception("Prediction failed")
        return jsonify(error="Prediction processing failed"), 500


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5050))
    app.run(host="127.0.0.1", port=port, debug=False)
