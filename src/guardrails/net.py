"""SSRF protection for outbound HTTP requests."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import urllib.request


class SSRFError(Exception):
    """Raised when a URL targets an internal/blocked address."""


_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_internal(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise SSRFError(f"Cannot resolve host: {host}")
    for _, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        for net in _BLOCKED_NETS:
            if ip in net:
                return True
    return False


def assert_url_allowed(url: str) -> None:
    """Raise ``SSRFError`` if *url* points to an internal address."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"Blocked scheme: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise SSRFError("No host in URL")
    if _is_internal(host):
        raise SSRFError(f"Blocked internal address: {host}")


def safe_get(url: str, timeout: int = 10) -> bytes:
    """Fetch *url* after SSRF validation.  Returns response body bytes."""
    assert_url_allowed(url)
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()
