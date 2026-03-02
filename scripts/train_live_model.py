from __future__ import annotations

import os
import sys

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/train_live_model.py data\\flow_baseline_XXXX.csv")
        raise SystemExit(2)

    path = sys.argv[1]
    df = pd.read_csv(path)
    X = df.values.astype(float)

    model = IsolationForest(
        n_estimators=250,
        contamination=0.02,
        random_state=42,
    )
    model.fit(X)

    os.makedirs("models", exist_ok=True)
    out_path = os.path.join("models", "live_isoforest.joblib")
    joblib.dump(model, out_path)
    print(f"Saved model to {out_path}")


if __name__ == "__main__":
    main()
