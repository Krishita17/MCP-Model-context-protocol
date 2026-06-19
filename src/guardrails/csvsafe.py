"""CSV formula injection prevention."""

from __future__ import annotations


_FORMULA_PREFIXES = ("=", "+", "-", "@")


def is_formula(text: str) -> bool:
    """Return ``True`` if *text* starts with a CSV formula trigger character."""
    return bool(text) and text[0] in _FORMULA_PREFIXES


def escape_formula(cell: str) -> str:
    """Prepend a tab to *cell* if it starts with a formula trigger character."""
    if is_formula(cell):
        return "\t" + cell
    return cell
