"""Safe string formatting that blocks template injection."""

from __future__ import annotations

import re


class TemplateInjectionError(Exception):
    """Raised when template injection patterns are detected."""


_DANGEROUS = re.compile(r"\{\{|\{%|<%|<\?|#\{|\$\{")


def safe_format(template: str, **kwargs: str) -> str:
    """Format *template* with ``str.format``, blocking injection patterns.

    Raises ``TemplateInjectionError`` if any value contains template syntax
    such as ``{{``, ``{%``, ``<%``, ``<?``, ``#{``, or ``${``.
    """
    for key, val in kwargs.items():
        if _DANGEROUS.search(str(val)):
            raise TemplateInjectionError(
                f"Injection pattern in value for {key!r}: {val!r}"
            )
    if _DANGEROUS.search(template):
        raise TemplateInjectionError(
            f"Injection pattern in template: {template!r}"
        )
    return template.format(**kwargs)
