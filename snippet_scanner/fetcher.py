"""Fetch a remote page for scanning, defensively.

The scanner accepts user-supplied URLs, which makes the scanner itself an SSRF
target. This module therefore:

* allows only ``http`` / ``https`` on ports 80 / 443 (unless overridden),
* resolves the hostname and refuses private, loopback, link-local, multicast,
  reserved and cloud-metadata addresses,
* follows redirects manually so that *every hop* is re-validated,
* connects to the vetted IP address (preventing DNS-rebinding between the
  check and the request) while keeping the original hostname for TLS/SNI,
* caps the response size and the total time spent.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import List
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

DEFAULT_TIMEOUT = 8  # seconds per socket operation
TOTAL_DEADLINE = 20  # seconds for the whole fetch, redirects and body included
MAX_REDIRECTS = 3
MAX_BYTES = 1_000_000
ALLOWED_PORTS = {80, 443}
USER_AGENT = "SnippetScanner/2.0 (+https://github.com/shankumar7/Snippet-scanner)"


class UnsafeURLError(ValueError):
    """The URL is malformed or points somewhere the scanner refuses to go."""


class FetchError(RuntimeError):
    """The page could not be retrieved."""


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public_ips(host: str, port: int, allow_private: bool = False) -> List[str]:
    """Resolve ``host`` and return its addresses, raising if any is non-public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"Could not resolve host '{host}'.") from exc
    addresses = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if not allow_private and not _is_public(ipaddress.ip_address(addr)):
            raise UnsafeURLError("The URL resolves to a private or reserved address, which is not allowed.")
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        raise FetchError(f"Could not resolve host '{host}'.")
    return addresses


def validate_url(url: str, allow_private: bool = False) -> str:
    """Return ``url`` if safe to fetch, else raise ``UnsafeURLError``."""
    if not isinstance(url, str) or not url.strip():
        raise UnsafeURLError("URL is empty.")
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeURLError("Only http:// and https:// URLs are allowed.")
    if not parts.hostname:
        raise UnsafeURLError("URL has no hostname.")
    if parts.username or parts.password:
        raise UnsafeURLError("URLs containing credentials are not allowed.")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeURLError("URL has an invalid port.") from exc
    if not allow_private and port not in ALLOWED_PORTS:
        raise UnsafeURLError("Only ports 80 and 443 are allowed.")
    resolve_public_ips(parts.hostname, port, allow_private)
    return url


class _TLSNameAdapter(HTTPAdapter):
    """HTTPS adapter that verifies the certificate (and sends SNI) for
    ``hostname`` even though the request URL contains a pinned IP address."""

    def __init__(self, hostname: str, **kwargs):
        self._hostname = hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["server_hostname"] = self._hostname
        pool_kwargs["assert_hostname"] = self._hostname
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


def fetch_url(url: str, allow_private: bool = False, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Download ``url`` (text) with SSRF protections and return the body."""
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    current = url
    deadline = time.monotonic() + TOTAL_DEADLINE
    try:
        for _ in range(MAX_REDIRECTS + 1):
            if time.monotonic() > deadline:
                raise FetchError("The remote server took too long to respond.")
            current = validate_url(current, allow_private)
            parts = urlsplit(current)
            request_url, headers = current, {}
            if not allow_private:
                # Pin the connection to the address we just vetted so a second
                # DNS lookup (DNS rebinding) cannot redirect us internally.
                port = parts.port or (443 if parts.scheme == "https" else 80)
                ip = resolve_public_ips(parts.hostname, port)[0]
                host = f"[{ip}]" if ":" in ip else ip
                netloc = host + (f":{parts.port}" if parts.port else "")
                request_url = parts._replace(netloc=netloc).geturl()
                headers["Host"] = parts.netloc
                if parts.scheme == "https":
                    session.mount("https://", _TLSNameAdapter(parts.hostname))
            try:
                resp = session.get(request_url, headers=headers, timeout=timeout,
                                   allow_redirects=False, stream=True)
            except requests.exceptions.RequestException as exc:
                raise FetchError(f"Failed to fetch the URL: {exc.__class__.__name__}") from exc

            with resp:
                if resp.is_redirect or resp.is_permanent_redirect:
                    location = resp.headers.get("Location")
                    if not location:
                        raise FetchError("Redirect without a Location header.")
                    current = urljoin(current, location)
                    continue
                if resp.status_code >= 400:
                    raise FetchError(f"The remote server answered with HTTP {resp.status_code}.")
                chunks, size = [], 0
                for chunk in resp.iter_content(chunk_size=16384):
                    if time.monotonic() > deadline:
                        raise FetchError("The remote server took too long to respond.")
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise FetchError(f"The page is larger than {MAX_BYTES:,} bytes.")
                    chunks.append(chunk)
                encoding = resp.encoding or resp.apparent_encoding or "utf-8"
                return b"".join(chunks).decode(encoding, errors="replace")
        raise FetchError("Too many redirects.")
    finally:
        session.close()
