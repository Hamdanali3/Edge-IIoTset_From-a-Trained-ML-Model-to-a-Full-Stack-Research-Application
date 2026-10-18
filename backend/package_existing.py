"""
Stage 4 — Package trusted model and fitted preprocessing into backend/models/model_bundle.joblib
Uses standard sklearn Pipeline + ColumnTransformer + FunctionTransformer(np.asarray, dtype=str)
+ OrdinalEncoder + StandardScaler + XGBClassifier so joblib.load() requires zero custom classes.
"""

from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OrdinalEncoder, FunctionTransformer

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
SOURCE = PROJECT_ROOT / "output" / "iot_intrusion_detector.pkl"

raw_bundle = joblib.load(SOURCE)
fitted_xgb = raw_bundle["model"]
fitted_scaler = raw_bundle["scaler"]
cat_encoders = raw_bundle["cat_encoders"]
FEATURES = list(raw_bundle["feature_columns"])
CLASS_NAMES = [str(c) for c in raw_bundle["class_names"]]
TASK = "classification"

# Build a fitted ColumnTransformer that preserves the EXACT 62-column order of FEATURES
transformers = []
max_cats = max(len(le.classes_) for le in cat_encoders.values())

# Construct a multi-row fit DataFrame covering all known training categories
fit_rows = []
for i in range(max_cats):
    r = {}
    for col in FEATURES:
        if col in cat_encoders:
            classes = list(cat_encoders[col].classes_)
            r[col] = str(classes[i % len(classes)])
        else:
            r[col] = 0.0
    fit_rows.append(r)
fit_df = pd.DataFrame(fit_rows, columns=FEATURES)

for col in FEATURES:
    if col in cat_encoders:
        le_col = cat_encoders[col]
        known_cats = np.asarray([str(x) for x in le_col.classes_], dtype=str)
        cat_pipe = Pipeline([
            ("to_str", FunctionTransformer(np.asarray, kw_args={"dtype": str})),
            ("ord", OrdinalEncoder(
                categories=[known_cats],
                handle_unknown="use_encoded_value",
                unknown_value=-1,
                dtype=np.float64,
            )),
        ])
        transformers.append((f"cat_{col}", cat_pipe, [col]))
    else:
        transformers.append((f"num_{col}", "passthrough", [col]))

ct = ColumnTransformer(transformers=transformers, remainder="drop")
ct.fit(fit_df)

if hasattr(fitted_scaler, "feature_names_in_"):
    delattr(fitted_scaler, "feature_names_in_")

pipeline = Pipeline([
    ("preprocess", ct),
    ("scaler", fitted_scaler),
    ("model", fitted_xgb),
])

assert hasattr(pipeline, "predict"), "Artifact must implement predict"
assert FEATURES and all(isinstance(x, str) for x in FEATURES)

bundle = {
    "pipeline": pipeline,
    "features": FEATURES,
    "class_names": CLASS_NAMES,
    "task": TASK,
    "model_version": "1.0",
}

models_dir = ROOT / "models"
models_dir.mkdir(parents=True, exist_ok=True)
joblib.dump(bundle, models_dir / "model_bundle.joblib")
print("Saved model bundle:", len(FEATURES), "features |", len(CLASS_NAMES), "classes")
