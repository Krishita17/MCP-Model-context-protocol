"""Tests for MCPShield policy engine."""

from pathlib import Path

import pytest

from mcpshield.policy_engine.engine import (
    PolicyEngine,
    PolicyRule,
    PolicyAction,
    PolicyDecision,
)


@pytest.fixture
def engine():
    e = PolicyEngine()
    e.add_rule(PolicyRule(
        rule_id="TEST-001",
        description="External tools cannot access filesystem",
        condition={"has_tag": "external", "requires_capability": "filesystem"},
        action=PolicyAction.BLOCK,
        compliance_refs=["SOC 2 CC6.1"],
        priority=100,
    ))
    e.add_rule(PolicyRule(
        rule_id="TEST-002",
        description="Credential access requires approval",
        condition={"requires_capability": "credential_access"},
        action=PolicyAction.REQUEST_APPROVAL,
        compliance_refs=["GDPR Art. 32"],
        priority=90,
    ))
    return e


class TestPolicyEngine:
    def test_no_rules_match_allows(self, engine):
        result = engine.evaluate("calculator", ["internal"], ["arithmetic"], [])
        assert result.decision == PolicyDecision.ALLOW
        assert len(result.matched_rules) == 0

    def test_block_external_filesystem(self, engine):
        result = engine.evaluate(
            "file_tool",
            ["external"],
            ["filesystem"],
            [],
        )
        assert result.decision == PolicyDecision.DENY
        assert any(r.rule_id == "TEST-001" for r in result.matched_rules)

    def test_require_approval_credentials(self, engine):
        result = engine.evaluate(
            "vault_tool",
            ["internal"],
            ["credential_access"],
            [],
        )
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL

    def test_compliance_evidence(self, engine):
        result = engine.evaluate("file_tool", ["external"], ["filesystem"], [])
        assert "SOC 2 CC6.1" in result.compliance_evidence

    def test_load_from_yaml(self, tmp_path):
        policy_file = tmp_path / "test_policy.yaml"
        policy_file.write_text("""
rules:
  - id: "YAML-001"
    description: "Block PII to external"
    condition:
      data_classification: "pii"
      has_tag: "external"
    action: "block"
    compliance_refs:
      - "GDPR Art. 5(1)(f)"
    priority: 100
""")
        engine = PolicyEngine()
        engine.load_policies(policy_file)
        result = engine.evaluate("sender", ["external"], [], ["pii"])
        assert result.decision == PolicyDecision.DENY
