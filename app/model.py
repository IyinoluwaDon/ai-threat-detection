import json

import joblib
import numpy as np

W_RF, W_ISO, THRESHOLD = 0.7, 0.3, 0.5


class Scorer:
    """Random Forest + Isolation Forest blended into one 0.0-1.0 threat score."""

    def __init__(self, model_dir: str = "models"):
        self.rf = joblib.load(f"{model_dir}/rf.joblib")
        self.iso = joblib.load(f"{model_dir}/iso.joblib")
        with open(f"{model_dir}/meta.json") as f:
            self.meta = json.load(f)

    def rf_proba(self, X):
        return self.rf.predict_proba(np.asarray(X, dtype=np.float32))[:, 1]

    def iso_anomaly(self, X):
        s = self.iso.score_samples(np.asarray(X, dtype=np.float32))
        p50, p1 = self.meta["iso_p50"], self.meta["iso_p1"]
        return np.clip((p50 - s) / (p50 - p1 + 1e-9), 0, 1)

    def score(self, X):
        return W_RF * self.rf_proba(X) + W_ISO * self.iso_anomaly(X)
