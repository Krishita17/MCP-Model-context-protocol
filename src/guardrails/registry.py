"""Tool registry integrity — detect shadowing and enforce allowlists."""

from __future__ import annotations

from collections import Counter
from typing import Sequence


class ToolShadowingError(Exception):
    """Raised when tool name collisions are detected."""


def find_collisions(tools: Sequence[dict]) -> list[str]:
    """Return tool names that appear more than once."""
    counts = Counter(t.get("name", "") for t in tools)
    return [name for name, c in counts.items() if c > 1]


def enforce_allowlist(tool: dict, allowed: set[str]) -> None:
    """Raise ``ToolShadowingError`` if *tool* name is not in *allowed*."""
    name = tool.get("name", "")
    if name not in allowed:
        raise ToolShadowingError(f"Tool {name!r} not in allowlist")


def assert_no_shadowing(tools: Sequence[dict]) -> None:
    """Raise ``ToolShadowingError`` if any tool name appears more than once."""
    dupes = find_collisions(tools)
    if dupes:
        raise ToolShadowingError(f"Duplicate tool names: {dupes}")
