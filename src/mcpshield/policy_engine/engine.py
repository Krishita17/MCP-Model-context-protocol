"""YAML-based policy engine for MCP tool access control — Layer 3 of MCPShield."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
import structlog

logger = structlog.get_logger()


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_human_approval"


class PolicyAction(str, Enum):
    EXECUTE = "execute"
    BLOCK = "block"
    REQUEST_APPROVAL = "request_approval"
    LOG_AND_ALLOW = "log_and_allow"


@dataclass
class PolicyRule:
    rule_id: str
    description: str
    condition: dict[str, Any]
    action: PolicyAction
    compliance_refs: list[str] = field(default_factory=list)
    priority: int = 0


@dataclass
class PolicyEvaluation:
    tool_name: str
    decision: PolicyDecision
    matched_rules: list[PolicyRule]
    compliance_evidence: list[str]
    explanation: str


class PolicyEngine:
    def __init__(self) -> None:
        self.rules: list[PolicyRule] = []
        self.log = logger.bind(component="policy_engine")

    def load_policies(self, policy_path: Path) -> None:
        data = yaml.safe_load(policy_path.read_text())
        for rule_data in data.get("rules", []):
            rule = PolicyRule(
                rule_id=rule_data["id"],
                description=rule_data["description"],
                condition=rule_data["condition"],
                action=PolicyAction(rule_data["action"]),
                compliance_refs=rule_data.get("compliance_refs", []),
                priority=rule_data.get("priority", 0),
            )
            self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        self.log.info("policies_loaded", count=len(self.rules))

    def add_rule(self, rule: PolicyRule) -> None:
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(
        self,
        tool_name: str,
        tool_tags: list[str],
        requested_capabilities: list[str],
        data_classifications: list[str],
    ) -> PolicyEvaluation:
        matched: list[PolicyRule] = []
        compliance_evidence: list[str] = []

        context = {
            "tool_name": tool_name,
            "tags": set(tool_tags),
            "capabilities": set(requested_capabilities),
            "data_classifications": set(data_classifications),
        }

        for rule in self.rules:
            if self._matches(rule.condition, context):
                matched.append(rule)
                compliance_evidence.extend(rule.compliance_refs)

        if not matched:
            return PolicyEvaluation(
                tool_name=tool_name,
                decision=PolicyDecision.ALLOW,
                matched_rules=[],
                compliance_evidence=[],
                explanation="No policy rules matched; default allow",
            )

        top_rule = matched[0]
        decision_map = {
            PolicyAction.BLOCK: PolicyDecision.DENY,
            PolicyAction.REQUEST_APPROVAL: PolicyDecision.REQUIRE_APPROVAL,
            PolicyAction.EXECUTE: PolicyDecision.ALLOW,
            PolicyAction.LOG_AND_ALLOW: PolicyDecision.ALLOW,
        }

        decision = decision_map[top_rule.action]

        return PolicyEvaluation(
            tool_name=tool_name,
            decision=decision,
            matched_rules=matched,
            compliance_evidence=list(set(compliance_evidence)),
            explanation=f"Rule '{top_rule.rule_id}': {top_rule.description}",
        )

    def _matches(self, condition: dict[str, Any], context: dict[str, Any]) -> bool:
        for key, expected in condition.items():
            if key == "tool_name":
                if context["tool_name"] != expected and expected != "*":
                    return False
            elif key == "has_tag":
                if expected not in context["tags"]:
                    return False
            elif key == "lacks_tag":
                if expected in context["tags"]:
                    return False
            elif key == "requires_capability":
                if expected not in context["capabilities"]:
                    return False
            elif key == "data_classification":
                if expected not in context["data_classifications"]:
                    return False
            elif key == "any_of":
                if not any(self._matches(sub, context) for sub in expected):
                    return False
            elif key == "all_of":
                if not all(self._matches(sub, context) for sub in expected):
                    return False
        return True
