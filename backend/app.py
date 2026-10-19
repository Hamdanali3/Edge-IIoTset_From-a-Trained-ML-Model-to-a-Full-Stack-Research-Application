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
      <li><strong>Prediction Endpoint (POST):</strong> <code>http://127.0.0.1:5050/predict</code></li>
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
