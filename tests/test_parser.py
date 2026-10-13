from app.parser import parse_line


def test_parses_normal_request():
    line = ('192.168.23.5 - - [12/Oct/2026:10:00:00 +0100] '
            '"GET /search?q=test HTTP/1.1" 200 512 "-" "Mozilla/5.0"')
    r = parse_line(line)
    assert r["ip"] == "192.168.23.5"
    assert r["path"] == "/search?q=test"
    assert r["status"] == "200"


def test_rejects_garbage():
    assert parse_line("not a log line") is None
