import os
import random

import numpy as np
import pytest
from sklearn.metrics import f1_score

from app.features import FEATURES

pytestmark = pytest.mark.skipif(
    not os.path.exists("models/rf.joblib"), reason="train first: python -m app.train")


def test_f1_gate_on_fresh_data():
    from app.gen_dataset import build
    from app.model import THRESHOLD, Scorer

    random.seed(7)
    rows = build(1000)
    X = np.array([[r[f] for f in FEATURES] for r in rows], dtype=np.float32)
    y = np.array([r["label"] for r in rows])
    cats = np.array([r["category"] for r in rows])
    pred = Scorer().score(X) >= THRESHOLD

    assert f1_score(y, pred) >= 0.95
    assert pred[y == 0].mean() <= 0.02             # false-positive ceiling
    assert pred[cats == "evasive"].mean() >= 0.90  # must beat the 0% rules baseline
