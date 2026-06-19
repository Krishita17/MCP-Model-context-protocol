"""Threat taxonomy mapping all 21 attack modules to OWASP LLM Top 10, CWE, and MITRE ATLAS."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class FrameworkRefs:
    """References to standard security frameworks."""
    owasp_llm: str          # e.g. "LLM01"
    cwe: int                # e.g. 74
    cwe_name: str           # e.g. "Improper Neutralization of Special Elements"
    atlas: Optional[str]    # e.g. "AML.T0043" or None


@dataclass(frozen=True)
class TaxonomyEntry:
    """A single attack module mapped to frameworks."""
    id: str                 # module identifier e.g. "description_injection"
    num: int                # ordinal 1-21
    title: str              # human-readable title
    owasp_label: str        # full OWASP category name
    refs: FrameworkRefs
    meta: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Full taxonomy of 21 attack modules
# ---------------------------------------------------------------------------

TAXONOMY: list[TaxonomyEntry] = [
    # --- Core 5 attack classes ---
    TaxonomyEntry(
        id="description_injection",
        num=1,
        title="Description Injection via Unicode Steganography",
        owasp_label="LLM01: Prompt Injection",
        refs=FrameworkRefs("LLM01", 74, "Improper Neutralization of Special Elements in Output", "AML.T0051"),
        meta={"severity": "critical", "crypto_blocks": True},
    ),
    TaxonomyEntry(
        id="tool_shadowing",
        num=2,
        title="Tool Shadowing / Name Collision",
        owasp_label="LLM05: Improper Output Handling",
        refs=FrameworkRefs("LLM05", 349, "Acceptance of Extraneous Untrusted Data With Trusted Data", "AML.T0043"),
        meta={"severity": "critical", "crypto_blocks": True},
    ),
    TaxonomyEntry(
        id="rug_pull",
        num=3,
        title="Rug Pull — Post-Approval Behavior Mutation",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 494, "Download of Code Without Integrity Check", "AML.T0044"),
        meta={"severity": "critical", "crypto_blocks": True},
    ),
    TaxonomyEntry(
        id="return_value_poisoning",
        num=4,
        title="Return Value Poisoning",
        owasp_label="LLM02: Insecure Output Handling",
        refs=FrameworkRefs("LLM02", 79, "Improper Neutralization of Input During Web Page Generation", None),
        meta={"severity": "high", "crypto_blocks": False},
    ),
    TaxonomyEntry(
        id="cross_tool_escalation",
        num=5,
        title="Cross-Tool Privilege Escalation",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 269, "Improper Privilege Management", "AML.T0040"),
        meta={"severity": "high", "crypto_blocks": False},
    ),
    # --- Guardrail bypass / evasion attacks ---
    TaxonomyEntry(
        id="path_traversal",
        num=6,
        title="Path Traversal via Tool Arguments",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 22, "Improper Limitation of a Pathname to a Restricted Directory", None),
        meta={"guardrail": "safe_resolve"},
    ),
    TaxonomyEntry(
        id="ssrf",
        num=7,
        title="Server-Side Request Forgery via Tool URLs",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 918, "Server-Side Request Forgery", None),
        meta={"guardrail": "assert_url_allowed"},
    ),
    TaxonomyEntry(
        id="command_injection",
        num=8,
        title="OS Command Injection via Tool Exec",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 78, "Improper Neutralization of Special Elements used in an OS Command", None),
        meta={"guardrail": "safe_run"},
    ),
    TaxonomyEntry(
        id="hidden_unicode",
        num=9,
        title="Hidden Unicode in Tool Descriptions",
        owasp_label="LLM01: Prompt Injection",
        refs=FrameworkRefs("LLM01", 116, "Improper Encoding or Escaping of Output", "AML.T0051"),
        meta={"guardrail": "has_hidden_unicode"},
    ),
    TaxonomyEntry(
        id="secret_leakage",
        num=10,
        title="Secret / API Key Leakage via Tool Output",
        owasp_label="LLM10: Model Theft",
        refs=FrameworkRefs("LLM10", 200, "Exposure of Sensitive Information to an Unauthorized Actor", None),
        meta={"guardrail": "find_secrets"},
    ),
    TaxonomyEntry(
        id="rate_limit_abuse",
        num=11,
        title="Rate Limit Bypass / Denial of Service",
        owasp_label="LLM04: Model Denial of Service",
        refs=FrameworkRefs("LLM04", 770, "Allocation of Resources Without Limits or Throttling", None),
        meta={"guardrail": "RateLimiter"},
    ),
    TaxonomyEntry(
        id="sql_injection",
        num=12,
        title="SQL Injection via Tool Arguments",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 89, "Improper Neutralization of Special Elements used in an SQL Command", None),
        meta={"guardrail": "safe_identifier"},
    ),
    TaxonomyEntry(
        id="template_injection",
        num=13,
        title="Template Injection via Format Strings",
        owasp_label="LLM01: Prompt Injection",
        refs=FrameworkRefs("LLM01", 1336, "Improper Neutralization of Special Elements Used in a Template Engine", None),
        meta={"guardrail": "safe_format"},
    ),
    TaxonomyEntry(
        id="unsafe_deserialization",
        num=14,
        title="Unsafe Deserialization of Tool Payloads",
        owasp_label="LLM05: Improper Output Handling",
        refs=FrameworkRefs("LLM05", 502, "Deserialization of Untrusted Data", None),
        meta={"guardrail": "safe_loads"},
    ),
    TaxonomyEntry(
        id="authorization_bypass",
        num=15,
        title="Authorization Bypass in Tool Access",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 862, "Missing Authorization", None),
        meta={"guardrail": "assert_owner"},
    ),
    TaxonomyEntry(
        id="unsafe_eval",
        num=16,
        title="Arbitrary Code Execution via Eval",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 95, "Improper Neutralization of Directives in Dynamically Evaluated Code", None),
        meta={"guardrail": "safe_eval"},
    ),
    TaxonomyEntry(
        id="csv_formula_injection",
        num=17,
        title="CSV Formula Injection in Exports",
        owasp_label="LLM02: Insecure Output Handling",
        refs=FrameworkRefs("LLM02", 1236, "Improper Neutralization of Formula Elements in a CSV File", None),
        meta={"guardrail": "escape_formula"},
    ),
    TaxonomyEntry(
        id="token_prediction",
        num=18,
        title="Predictable Token / Session Forgery",
        owasp_label="LLM10: Model Theft",
        refs=FrameworkRefs("LLM10", 330, "Use of Insufficiently Random Values", None),
        meta={"guardrail": "new_token"},
    ),
    TaxonomyEntry(
        id="control_char_injection",
        num=19,
        title="Control Character Injection in Output Framing",
        owasp_label="LLM02: Insecure Output Handling",
        refs=FrameworkRefs("LLM02", 116, "Improper Encoding or Escaping of Output", None),
        meta={"guardrail": "strip_control"},
    ),
    TaxonomyEntry(
        id="approval_bypass",
        num=20,
        title="Human Approval Gate Bypass",
        owasp_label="LLM06: Excessive Agency",
        refs=FrameworkRefs("LLM06", 863, "Incorrect Authorization", None),
        meta={"guardrail": "require"},
    ),
    TaxonomyEntry(
        id="tool_registry_collision",
        num=21,
        title="Tool Registry Collision / Shadowing via Registry",
        owasp_label="LLM05: Improper Output Handling",
        refs=FrameworkRefs("LLM05", 349, "Acceptance of Extraneous Untrusted Data With Trusted Data", "AML.T0043"),
        meta={"guardrail": "find_collisions"},
    ),
]

BY_ID: dict[str, TaxonomyEntry] = {e.id: e for e in TAXONOMY}


def owasp_coverage() -> dict[str, list[str]]:
    """Return a mapping of OWASP LLM category code -> list of module IDs."""
    result: dict[str, list[str]] = {}
    for entry in TAXONOMY:
        code = entry.refs.owasp_llm
        result.setdefault(code, []).append(entry.id)
    return result
