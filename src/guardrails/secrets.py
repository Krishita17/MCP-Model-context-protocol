"""Secret detection and redaction."""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    ("Generic API Key", re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})")),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Password Field", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?(\S{6,})")),
    ("Private Key", re.compile(r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----")),
    ("Slack Token", re.compile(r"xox[bpors]-[A-Za-z0-9\-]+")),
    ("Generic Secret", re.compile(r"(?i)(?:secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})")),
]


def find_secrets(text: str) -> list[dict[str, str]]:
    """Return list of ``{"type": ..., "match": ...}`` for each secret found."""
    results: list[dict[str, str]] = []
    for name, pat in _PATTERNS:
        for m in pat.finditer(text):
            results.append({"type": name, "match": m.group(0)})
    return results


def scrub(text: str) -> str:
    """Replace detected secrets with ``[REDACTED]``."""
    out = text
    for _, pat in _PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out
