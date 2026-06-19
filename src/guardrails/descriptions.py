"""Tool description sanitization and prompt-injection detection."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata


_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|above)\s+(instructions|prompts)", re.I),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\s*/?\s*(?:system|prompt|instruction)", re.I),
    re.compile(r"\bdo\s+not\s+follow\b", re.I),
    re.compile(r"\bact\s+as\b", re.I),
    re.compile(r"\bpretend\s+(?:you(?:'re|are)?|to\s+be)\b", re.I),
    re.compile(r"\brole\s*:\s*(?:system|admin|root)\b", re.I),
]

_HIDDEN_CATEGORIES = {"Cf", "Mn", "Cc"}

_HOMOGLYPH_MAP: dict[int, str] = {
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p",
    0x0441: "c", 0x0443: "y", 0x0445: "x", 0x0455: "s",
    0x0456: "i", 0x04BB: "h", 0xFF41: "a", 0xFF45: "e",
}


def sanitize_description(text: str) -> str:
    """Strip hidden Unicode and control characters from *text*."""
    return "".join(
        ch for ch in text
        if unicodedata.category(ch) not in _HIDDEN_CATEGORIES
    )


def find_injection(text: str) -> list[str]:
    """Return list of prompt-injection pattern matches found in *text*."""
    hits: list[str] = []
    for pat in _INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(m.group(0))
    return hits


def has_hidden_unicode(text: str) -> bool:
    """Detect zero-width characters and Cyrillic/fullwidth homoglyphs."""
    for ch in text:
        if unicodedata.category(ch) in _HIDDEN_CATEGORIES:
            return True
        if ord(ch) in _HOMOGLYPH_MAP:
            return True
    return False


def tool_fingerprint(tool: dict) -> str:
    """Return SHA-256 hex digest of *tool*'s canonical JSON."""
    canon = json.dumps(tool, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()
