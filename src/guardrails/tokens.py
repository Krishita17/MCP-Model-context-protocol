"""Cryptographically secure token generation."""

from __future__ import annotations

import hmac
import secrets


def new_token(nbytes: int = 32) -> str:
    """Return a URL-safe base64 token with *nbytes* of randomness."""
    return secrets.token_urlsafe(nbytes)


def new_hex_token(nbytes: int = 32) -> str:
    """Return a hex token with *nbytes* of randomness."""
    return secrets.token_hex(nbytes)


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    """Compare two values in constant time to prevent timing attacks."""
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)
