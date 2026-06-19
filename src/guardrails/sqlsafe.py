"""SQL identifier validation and LIKE escaping."""

from __future__ import annotations

import re


class SQLIdentifierError(Exception):
    """Raised for invalid SQL identifiers."""


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def safe_identifier(name: str) -> str:
    """Validate *name* as a safe SQL identifier and return it.

    Only allows ``[A-Za-z_][A-Za-z0-9_]*`` up to 128 chars.
    """
    if not _IDENT_RE.match(name):
        raise SQLIdentifierError(f"Invalid SQL identifier: {name!r}")
    return name


def like_escape(text: str, escape_char: str = "\\") -> str:
    """Escape SQL LIKE wildcards (``%``, ``_``) in *text*."""
    text = text.replace(escape_char, escape_char + escape_char)
    text = text.replace("%", escape_char + "%")
    text = text.replace("_", escape_char + "_")
    return text
