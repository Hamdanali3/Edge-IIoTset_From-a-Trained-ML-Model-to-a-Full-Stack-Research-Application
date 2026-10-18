from pathlib import Path
import json
import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
bundle = joblib.load(ROOT / "backend/models/model_bundle.joblib")
with (ROOT / "backend/test_payload.json").open(encoding="utf-8") as f:
    payload = json.load(f)
features = bundle["features"]
assert set(features) == set(payload), "Payload keys must match features"
frame = pd.DataFrame([[payload[f] for f in features]], columns=features)
model = bundle["pipeline"]
pred_idx = model.predict(frame).tolist()
class_names = bundle.get("class_names", [])
pred_labels = [class_names[i] if i < len(class_names) else i for i in pred_idx]
print("Prediction:", pred_idx, "-> Label:", pred_labels)
if hasattr(model, "predict_proba"):
    print("Probabilities:", model.predict_proba(frame).tolist())
print("PASS: local inference")
