"""Subprocess execution with command allowlisting."""

from __future__ import annotations

import shlex
import subprocess
from typing import Sequence


class CommandNotAllowed(Exception):
    """Raised when a command is not on the allowlist."""


def safe_run(
    command: str,
    allowlist: Sequence[str],
    *,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Run *command* only if its executable is in *allowlist*.

    The command is split with ``shlex`` and executed **without** ``shell=True``.
    """
    parts = shlex.split(command)
    if not parts:
        raise CommandNotAllowed("Empty command")
    exe = parts[0]
    if exe not in allowlist:
        raise CommandNotAllowed(
            f"Command {exe!r} not in allowlist {list(allowlist)}"
        )
    return subprocess.run(
        parts,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
