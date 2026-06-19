"""Safe deserialization — blocks pickle and other unsafe formats."""

from __future__ import annotations

import json


class UnsafeDeserialization(Exception):
    """Raised when unsafe serialization format is detected."""


_PICKLE_HEADERS = [
    b"\x80\x02",  # Protocol 2
    b"\x80\x03",  # Protocol 3
    b"\x80\x04",  # Protocol 4
    b"\x80\x05",  # Protocol 5
    b"cos\n",     # Protocol 0 (global opcode)
    b"c__builtin__",
]


def looks_like_pickle(data: bytes) -> bool:
    """Return ``True`` if *data* starts with a known pickle header."""
    for hdr in _PICKLE_HEADERS:
        if data.startswith(hdr):
            return True
    return False


def safe_loads(data: bytes | str) -> object:
    """Deserialize JSON *data*, rejecting anything that looks like pickle.

    Raises ``UnsafeDeserialization`` for non-JSON formats.
    """
    raw = data if isinstance(data, bytes) else data.encode()
    if looks_like_pickle(raw):
        raise UnsafeDeserialization("Data appears to be pickle — rejected")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UnsafeDeserialization(f"Not valid JSON: {exc}") from exc
