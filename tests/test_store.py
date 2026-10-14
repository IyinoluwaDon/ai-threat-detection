from app.store import Store


def test_roundtrip(tmp_path):
    s = Store(str(tmp_path / "a.db"))
    a = s.add({"ts": "t", "ip": "1.1.1.1", "method": "GET", "path": "/x", "ua": "u",
               "rules": ["sqli"], "score": 0.9, "severity": "critical", "source": "both"})
    assert a["id"] == 1
    assert s.recent()[0]["rules"] == ["sqli"]
    st = s.stats()
    assert st["total"] == 1 and st["by_severity"]["critical"] == 1
    assert st["top_ips"][0]["ip"] == "1.1.1.1"
