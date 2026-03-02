from __future__ import annotations

import os
import sys

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/train_nsl_kdd.py path\\to\\nsl_kdd.csv")
        raise SystemExit(2)

    df = pd.read_csv(sys.argv[1])
    label_col = "label" if "label" in df.columns else ("class" if "class" in df.columns else None)
    if not label_col:
        raise ValueError("Expected label column named label or class")

    y_raw = df[label_col].astype(str)
    X = df.drop(columns=[label_col])

    y = (y_raw != "normal").astype(int)

    categorical = [c for c in X.columns if X[c].dtype == "object"]
    numeric = [c for c in X.columns if c not in categorical]

    pre = ColumnTransformer(
        transformers=[
            ("num", Pipeline([("scaler", StandardScaler())]), numeric),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
        ]
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    pipe = Pipeline([("pre", pre), ("clf", clf)])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    print(f"Accuracy  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"Recall    {recall_score(y_test, y_pred, zero_division=0):.4f}")

    os.makedirs("models", exist_ok=True)
    out_path = os.path.join("models", "nsl_kdd_random_forest.joblib")
    joblib.dump(pipe, out_path)
    print(f"Saved model to {out_path}")


if __name__ == "__main__":
    main()
