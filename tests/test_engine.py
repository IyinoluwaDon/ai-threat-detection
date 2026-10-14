import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.path.exists("models/rf.joblib"), reason="train first: python -m app.train")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


@pytest.fixture(scope="module")
def engine():
    from app.engine import Engine
    return Engine()


def rec(path, ua=UA, method="GET"):
    return {"ip": "10.0.0.9", "path": path, "ua": ua, "method": method}


def test_benign_no_alert(engine):
    assert engine.analyze(rec("/profile?id=3")) is None


def test_classic_attack_flagged_by_rules(engine):
    a = engine.analyze(rec("/search?q=1%27%20OR%201=1--"))
    assert a and "sqli" in a["rules"] and a["severity"] in ("high", "critical")


def test_evasive_attack_caught_by_ml_only(engine):
    a = engine.analyze(rec("/c?x=%3Cdetails/open/ontoggle=alert(1)%3E"))
    assert a and a["source"] == "ml" and a["rules"] == []


def test_recon_caught_by_ml(engine):
    a = engine.analyze(rec("/.env"))
    assert a and a["source"] == "ml"
