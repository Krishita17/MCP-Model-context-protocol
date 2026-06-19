"""Human-in-the-loop approval gate."""

from __future__ import annotations

from typing import Callable


class ApprovalDenied(Exception):
    """Raised when an action is denied by the approver."""


def require(
    action: str,
    approver: Callable[[str], bool],
) -> None:
    """Ask *approver* to approve *action*.  Raises ``ApprovalDenied`` on denial.

    *approver* is a callable that receives a description string and returns
    ``True`` to approve or ``False`` to deny.
    """
    if not approver(action):
        raise ApprovalDenied(f"Action denied: {action}")
