"""MCP Security Guardrails Library."""

from .paths import safe_resolve, PathTraversalError
from .net import safe_get, assert_url_allowed, SSRFError
from .exec_guard import safe_run, CommandNotAllowed
from .descriptions import (
    sanitize_description,
    find_injection,
    has_hidden_unicode,
    tool_fingerprint,
)
from .secrets import find_secrets, scrub
from .ratelimit import RateLimiter, RateLimitExceeded
from .sqlsafe import safe_identifier, like_escape, SQLIdentifierError
from .templating import safe_format, TemplateInjectionError
from .serialization import safe_loads, looks_like_pickle, UnsafeDeserialization
from .authz import assert_owner, can_access, require_scope, AuthorizationError
from .safe_eval import safe_eval, UnsafeExpression
from .csvsafe import escape_formula, is_formula
from .tokens import new_token, new_hex_token, constant_time_compare
from .framing import strip_control, sanitize_output, frame_untrusted
from .approval import require, ApprovalDenied
from .registry import (
    find_collisions,
    enforce_allowlist,
    assert_no_shadowing,
    ToolShadowingError,
)

__all__ = [
    "safe_resolve", "PathTraversalError",
    "safe_get", "assert_url_allowed", "SSRFError",
    "safe_run", "CommandNotAllowed",
    "sanitize_description", "find_injection", "has_hidden_unicode", "tool_fingerprint",
    "find_secrets", "scrub",
    "RateLimiter", "RateLimitExceeded",
    "safe_identifier", "like_escape", "SQLIdentifierError",
    "safe_format", "TemplateInjectionError",
    "safe_loads", "looks_like_pickle", "UnsafeDeserialization",
    "assert_owner", "can_access", "require_scope", "AuthorizationError",
    "safe_eval", "UnsafeExpression",
    "escape_formula", "is_formula",
    "new_token", "new_hex_token", "constant_time_compare",
    "strip_control", "sanitize_output", "frame_untrusted",
    "require", "ApprovalDenied",
    "find_collisions", "enforce_allowlist", "assert_no_shadowing", "ToolShadowingError",
]
