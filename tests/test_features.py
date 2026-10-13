from app.features import FEATURES, extract


def rec(path, ua="Mozilla/5.0", method="GET"):
    return {"path": path, "ua": ua, "method": method}


def feats(r):
    return dict(zip(FEATURES, extract(r)))


def test_vector_length():
    assert len(extract(rec("/"))) == len(FEATURES)


def test_attack_features_higher():
    b = feats(rec("/search?q=laptop"))
    a = feats(rec("/search?q=1%27%20UNION%20SELECT%20null--"))
    assert a["special_ratio"] > b["special_ratio"]
    assert a["sql_kw"] >= 2 and b["sql_kw"] == 0
    assert a["quotes"] == 1


def test_tool_ua_flag():
    assert feats(rec("/", ua="sqlmap/1.8"))["ua_tool"] == 1
    assert feats(rec("/"))["ua_tool"] == 0


def test_empty_input_is_safe():
    assert all(isinstance(x, float) for x in extract(rec("")))
