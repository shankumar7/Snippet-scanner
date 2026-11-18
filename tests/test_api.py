import snippet_scanner.api as api_module
from snippet_scanner.fetcher import FetchError


def post(client, payload=None, **kw):
    return client.post("/scan", json=payload, **kw)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.get_json()["status"] == "ok"


def test_rules_listing(client):
    body = client.get("/rules").get_json()
    assert body["count"] == len(body["rules"]) > 20
    categories = {r["owasp_category"][:3] for r in body["rules"]}
    assert categories == {f"A{n:02d}" for n in range(1, 11)}  # all ten categories covered


def test_scan_code_snippet(client):
    r = post(client, {"code_snippet": "password = 'hunter2hunter2'"})
    body = r.get_json()
    assert r.status_code == 200 and body["status"] == "success"
    assert body["counts"]["total"] == len(body["vulnerabilities"]) == 1
    assert body["vulnerabilities"][0]["owasp_category"].startswith("A02")


def test_clean_code_returns_empty(client):
    body = post(client, {"code_snippet": "x = 1"}).get_json()
    assert body["vulnerabilities"] == [] and body["counts"]["total"] == 0


def test_bad_payloads(client):
    assert post(client, None).status_code == 400
    assert client.post("/scan", data="not json", content_type="text/plain").status_code == 400
    assert post(client, {}).status_code == 400
    assert post(client, {"code_snippet": "   "}).status_code == 400
    assert post(client, {"code_snippet": 123}).status_code == 400
    assert post(client, [1, 2]).status_code == 400


def test_errors_are_json(client):
    r = client.get("/nope")
    assert r.status_code == 404 and r.get_json()["status"] == "error"
    r = client.get("/scan")
    assert r.status_code == 405 and r.get_json()["status"] == "error"


def test_oversized_body(client):
    r = post(client, {"code_snippet": "a" * (3 * 1024 * 1024)})
    assert r.status_code == 413 and r.get_json()["status"] == "error"


def test_oversized_snippet_under_body_limit(client):
    r = post(client, {"code_snippet": "a" * 1_500_000})
    assert r.status_code == 413


def test_url_scan_uses_fetcher(client, monkeypatch):
    monkeypatch.setattr(api_module, "fetch_url", lambda url, allow_private=False: "app.run(debug=True)")
    body = post(client, {"url": "https://example.com"}).get_json()
    assert body["vulnerabilities"][0]["rule_id"] == "A05-DEBUG-ENABLED"


def test_url_fetch_failure_is_502(client, monkeypatch):
    def boom(url, allow_private=False):
        raise FetchError("nope")
    monkeypatch.setattr(api_module, "fetch_url", boom)
    r = post(client, {"url": "https://example.com"})
    assert r.status_code == 502 and r.get_json()["status"] == "error"


def test_ssrf_targets_rejected(client):
    for bad in [
        "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/", "http://10.0.0.5/", "http://192.168.1.1/", "http://0.0.0.0/",
        "http://2130706433/", "file:///etc/passwd", "ftp://example.com/", "gopher://x/",
        "http://user:pw@example.com/", "https://example.com:6379/", "javascript:alert(1)",
    ]:
        r = post(client, {"url": bad})
        assert r.status_code in (400, 502), bad
        assert r.get_json()["status"] == "error", bad


def test_cors_header(client):
    r = client.post("/scan", json={"code_snippet": "x"}, headers={"Origin": "https://snippet-scanner.pages.dev"})
    assert r.headers.get("Access-Control-Allow-Origin") in ("*", "https://snippet-scanner.pages.dev")


def test_serves_frontend(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Snippet" in r.data


def test_serves_stylesheet(client):
    r = client.get("/tailwind.css")
    assert r.status_code == 200 and r.mimetype == "text/css"
