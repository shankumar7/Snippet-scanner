import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from snippet_scanner import fetcher
from snippet_scanner.fetcher import FetchError, UnsafeURLError, fetch_url, validate_url


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect-private":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        elif self.path == "/big":
            body = b"a" * (fetcher.MAX_BYTES + 10)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/404":
            self.send_response(404)
            self.end_headers()
        else:
            body = b"app.run(debug=True)"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_fetch_local_when_private_allowed(server):
    assert fetch_url(server + "/", allow_private=True) == "app.run(debug=True)"


def test_loopback_blocked_by_default(server):
    with pytest.raises(UnsafeURLError):
        fetch_url(server + "/")


def test_http_error_status(server):
    with pytest.raises(FetchError):
        fetch_url(server + "/404", allow_private=True)


def test_size_limit(server):
    with pytest.raises(FetchError, match="larger"):
        fetch_url(server + "/big", allow_private=True)


def test_redirect_loop_stops(server):
    with pytest.raises(FetchError, match="redirect"):
        fetch_url(server + "/loop", allow_private=True)


def test_redirect_to_private_address_is_blocked(monkeypatch, server):
    """A public host that redirects to the metadata IP must be refused on the hop."""
    real = socket.getaddrinfo

    def fake(host, port, *a, **k):
        if host == "public.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return real(host, port, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    calls = []

    class Resp:
        status_code, is_redirect, is_permanent_redirect = 302, True, False
        headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def fake_get(self, url, **kw):
        calls.append(url)
        return Resp()

    monkeypatch.setattr("requests.Session.get", fake_get)
    with pytest.raises(UnsafeURLError):
        fetch_url("http://public.test/")
    assert len(calls) == 1  # never requested the metadata address
    assert "93.184.216.34" in calls[0]  # connection pinned to the vetted IP


def test_hostname_resolving_to_private_ip_blocked(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port))],
    )
    with pytest.raises(UnsafeURLError):
        validate_url("http://internal.corp.example/")


def test_mixed_dns_answer_blocked(monkeypatch):
    answers = [("93.184.216.34", 80), ("127.0.0.1", 80)]
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", a_) for a_ in answers],
    )
    with pytest.raises(UnsafeURLError):
        validate_url("http://mixed.example/")


def test_ipv4_mapped_ipv6_blocked():
    with pytest.raises(UnsafeURLError):
        validate_url("http://[::ffff:127.0.0.1]/")


@pytest.mark.parametrize("url", ["", "   ", "http://", "ftp://x.test", "http://u:p@x.test", "https://x.test:99999"])
def test_malformed_urls(url):
    with pytest.raises(UnsafeURLError):
        validate_url(url)


# --------------------------------------------------------------- TLS pinning
import shutil
import ssl
import subprocess


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not available")
def test_https_pinned_ip_still_verifies_hostname(tmp_path, monkeypatch):
    """The request goes to a vetted IP, but the certificate is checked against
    the original hostname (and SNI carries it)."""
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-subj", "/CN=pinned.test", "-addext", "subjectAltName=DNS:pinned.test"],
        check=True, capture_output=True)

    seen = {}

    class H(Handler):
        def do_GET(self):
            seen["host"] = self.headers.get("Host")
            super().do_GET()

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    def sni(sock, name, _ctx):
        seen["sni"] = name

    ctx.sni_callback = sni
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_port

    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(cert))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setattr(fetcher, "ALLOWED_PORTS", {port})
    monkeypatch.setattr(fetcher, "_is_public", lambda ip: True)  # treat our loopback server as "public"
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))])
    try:
        assert fetch_url(f"https://pinned.test:{port}/") == "app.run(debug=True)"
        assert seen["sni"] == "pinned.test"
        assert seen["host"] == f"pinned.test:{port}"

        # A certificate for a *different* name must be rejected.
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda host, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))])
        with pytest.raises(FetchError):
            fetch_url(f"https://other.test:{port}/")
    finally:
        srv.shutdown()


def test_total_deadline_enforced(server, monkeypatch):
    monkeypatch.setattr(fetcher, "TOTAL_DEADLINE", -1)
    with pytest.raises(FetchError, match="too long"):
        fetch_url(server + "/", allow_private=True)
