"""Authorization helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class AuthorizationError(Exception):
    """Raised when an authorization check fails."""


@dataclass
class Resource:
    id: str
    owner: str
    acl: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class Token:
    sub: str
    scopes: set[str] = field(default_factory=set)


def assert_owner(user: str, resource: Resource) -> None:
    """Raise ``AuthorizationError`` unless *user* owns *resource*."""
    if resource.owner != user:
        raise AuthorizationError(
            f"User {user!r} does not own resource {resource.id!r}"
        )


def can_access(user: str, resource: Resource, action: str) -> bool:
    """Return ``True`` if *user* may perform *action* on *resource*."""
    if resource.owner == user:
        return True
    allowed = resource.acl.get(user, set())
    return action in allowed or "*" in allowed


def require_scope(token: Token, scope: str) -> None:
    """Raise ``AuthorizationError`` unless *token* has *scope*."""
    if scope not in token.scopes and "*" not in token.scopes:
        raise AuthorizationError(
            f"Token for {token.sub!r} missing scope {scope!r}"
        )
