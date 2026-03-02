from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import joblib
import numpy as np


@dataclass
class DetectionResult:
    is_anomaly: bool
    score: float


class AnomalyModel:
    def __init__(self, model_path: str) -> None:
        self.model = joblib.load(model_path)

    def infer(self, vector: Sequence[float]) -> DetectionResult:
        X = np.array([list(vector)], dtype=float)
        pred = self.model.predict(X)[0]
        is_anom = bool(pred == -1)

        try:
            normality = float(self.model.decision_function(X)[0])
            score = -normality
        except Exception:
            score = 0.0

        return DetectionResult(is_anomaly=is_anom, score=score)
