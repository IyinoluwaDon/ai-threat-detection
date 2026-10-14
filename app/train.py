import csv
import json
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from app.features import FEATURES
from app.model import THRESHOLD, Scorer


def load(path="data/dataset.csv"):
    X, y, cat, rules = [], [], [], []
    with open(path) as f:
        for r in csv.DictReader(f):
            X.append([float(r[k]) for k in FEATURES])
            y.append(int(r["label"]))
            cat.append(r["category"])
            rules.append(int(r["rules_flag"]))
    return np.array(X, dtype=np.float32), np.array(y), np.array(cat), np.array(rules)


def prf(y, pred):
    return {"precision": round(float(precision_score(y, pred)), 4),
            "recall": round(float(recall_score(y, pred)), 4),
            "f1": round(float(f1_score(y, pred)), 4)}


def rf_model():
    return RandomForestClassifier(n_estimators=200, max_depth=14, class_weight="balanced",
                                  random_state=42, n_jobs=-1)


def main():
    X, y, cat, rules = load()
    Xtr, Xte, ytr, yte, ctr, cte, _, rte = train_test_split(
        X, y, cat, rules, test_size=0.25, stratify=y, random_state=42)

    rf = rf_model().fit(Xtr, ytr)
    iso = IsolationForest(n_estimators=200, random_state=42, n_jobs=-1).fit(Xtr[ytr == 0])
    bs = iso.score_samples(Xtr[ytr == 0])
    meta = {"iso_p50": float(np.median(bs)), "iso_p1": float(np.percentile(bs, 1))}

    os.makedirs("models", exist_ok=True)
    joblib.dump(rf, "models/rf.joblib")
    joblib.dump(iso, "models/iso.joblib")
    with open("models/meta.json", "w") as f:
        json.dump(meta, f)

    sc = Scorer()
    blend = sc.score(Xte) >= THRESHOLD
    rf_only = sc.rf_proba(Xte) >= 0.5
    iso_only = sc.iso_anomaly(Xte) >= 0.5

    # unseen-family test: never show the model evasive attacks during training
    keep = ctr != "evasive"
    rf2 = rf_model().fit(Xtr[keep], ytr[keep])
    ev = cte == "evasive"

    results = {
        "rules": prf(yte, rte), "random_forest": prf(yte, rf_only),
        "isolation_forest": prf(yte, iso_only), "ensemble": prf(yte, blend),
        "ensemble_false_positive_rate": round(float(blend[yte == 0].mean()), 4),
        "recall_by_category": {
            c: {"rules": round(float(rte[cte == c].mean()), 4),
                "ensemble": round(float(blend[cte == c].mean()), 4)}
            for c in ("classic", "evasive", "recon")},
        "unseen_evasive_recall_rf": round(float(rf2.predict(Xte[ev]).mean()), 4),
    }
    with open("models/metrics.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"{'model':<18}{'precision':>10}{'recall':>9}{'f1':>8}")
    for k in ("rules", "random_forest", "isolation_forest", "ensemble"):
        r = results[k]
        print(f"{k:<18}{r['precision']:>10}{r['recall']:>9}{r['f1']:>8}")
    print("ensemble FP rate:", results["ensemble_false_positive_rate"])
    print("recall by category:", json.dumps(results["recall_by_category"]))
    print("evasive recall when UNSEEN in training (RF):", results["unseen_evasive_recall_rf"])


if __name__ == "__main__":
    main()
