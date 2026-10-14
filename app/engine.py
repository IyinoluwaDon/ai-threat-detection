import time
from typing import Optional

from app.features import extract
from app.model import THRESHOLD, Scorer
from app.rules import detect


class Engine:
    """Combines regex rules and the ML ensemble into one alert decision."""

    def __init__(self, scorer: Optional[Scorer] = None):
        self.scorer = scorer or Scorer()

    def analyze(self, rec: dict) -> Optional[dict]:
        rules = detect(rec)
        score = float(self.scorer.score([extract(rec)])[0])
        if not rules and score < THRESHOLD:
            return None
        source = "both" if rules and score >= THRESHOLD else ("rules" if rules else "ml")
        severity = "medium"
        if score >= 0.7:
            severity = "high"
        if score >= 0.9:
            severity = "critical"
        if rules and severity == "medium":
            severity = "high"
        return {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ip": rec.get("ip", "-"),
            "method": rec.get("method", "-"),
            "path": rec.get("path", "-"),
            "ua": rec.get("ua", "-"),
            "rules": rules,
            "score": round(score, 4),
            "severity": severity,
            "source": source,
        }
