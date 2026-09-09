"""
train_model.py
---------------
Trains a small RandomForestClassifier that predicts "attack_likelihood"
(Low / Medium / High) for a vulnerability, based on:
    - cvss_score
    - exploit_available
    - patch_available
    - days_since_disclosure
    - exposure (Internal/External)
    - category (type of vulnerability)

This is intentionally simple (a classroom-appropriate model), but the
pipeline (encoding + scaling + classifier bundled together) is set up the
way a real project would do it, so you can swap in real historical
incident data later without rewriting the app.

Run:
    python model/train_model.py
"""

import os
import pandas as pd
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "..", "data", "training_data.csv")
MODEL_PATH = os.path.join(HERE, "risk_model.pkl")

NUMERIC_FEATURES = ["cvss_score", "exploit_available", "patch_available", "days_since_disclosure"]
CATEGORICAL_FEATURES = ["exposure", "category"]
TARGET = "attack_likelihood"


def main():
    df = pd.read_csv(DATA_PATH)

    X = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES]
    y = df[TARGET]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=8, random_state=42, class_weight="balanced"
    )

    pipeline = Pipeline(steps=[("preprocess", preprocessor), ("model", clf)])
    pipeline.fit(X_train, y_train)

    preds = pipeline.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Test accuracy: {acc:.3f}")
    print(classification_report(y_test, preds))

    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
