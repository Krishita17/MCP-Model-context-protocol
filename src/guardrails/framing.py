"""Output sanitization — strip control characters and frame untrusted content."""

from __future__ import annotations

import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_control(text: str) -> str:
    """Remove ANSI escape sequences and ASCII control characters."""
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    return text


def sanitize_output(text: str) -> str:
    """Sanitize LLM output by stripping control chars and trimming."""
    return strip_control(text).strip()


def frame_untrusted(text: str) -> str:
    """Wrap untrusted content with clear boundary markers."""
    clean = strip_control(text)
    return (
        "--- BEGIN UNTRUSTED CONTENT ---\n"
        f"{clean}\n"
        "--- END UNTRUSTED CONTENT ---"
    )
