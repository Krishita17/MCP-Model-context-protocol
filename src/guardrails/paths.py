"""Path traversal prevention."""

from pathlib import Path


class PathTraversalError(Exception):
    """Raised when a path escapes the allowed root."""


def safe_resolve(root: str | Path, user_path: str | Path) -> Path:
    """Resolve *user_path* under *root*, blocking directory traversal.

    Returns the resolved absolute path.  Raises ``PathTraversalError`` if the
    resolved path is outside *root*.
    """
    root = Path(root).resolve()
    target = (root / Path(user_path)).resolve()
    if not (target == root or str(target).startswith(str(root) + "/")):
        raise PathTraversalError(
            f"Path {user_path!r} resolves outside root {root}"
        )
    return target
