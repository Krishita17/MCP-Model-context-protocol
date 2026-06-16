"""MCP Shared Responsibility Model — defines obligations for each ecosystem actor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActorRole(str, Enum):
    PLATFORM_DEVELOPER = "ai_platform_developer"
    SERVER_PUBLISHER = "mcp_server_publisher"
    ENTERPRISE_DEPLOYER = "enterprise_deployer"
    END_USER = "end_user"


class LiabilityType(str, Enum):
    PRODUCT_LIABILITY = "product_liability"
    DATA_CONTROLLER = "data_controller"
    DATA_PROCESSOR = "data_processor"
    FRAUD = "fraud"
    NEGLIGENCE = "negligence"
    BREACH_NOTIFICATION = "breach_notification"
    REGULATORY_FINE = "regulatory_fine"


@dataclass
class SecurityObligation:
    obligation_id: str
    description: str
    actor: ActorRole
    controls: list[str]
    regulatory_refs: list[str]
    verification_method: str


@dataclass
class LiabilityMapping:
    attack_class: str
    actor: ActorRole
    liability_type: LiabilityType
    regulatory_basis: str
    max_exposure: str
    mitigation: str


@dataclass
class SharedResponsibilityModel:
    obligations: list[SecurityObligation] = field(default_factory=list)
    liability_mappings: list[LiabilityMapping] = field(default_factory=list)

    def get_obligations_for(self, actor: ActorRole) -> list[SecurityObligation]:
        return [o for o in self.obligations if o.actor == actor]

    def get_liabilities_for(self, actor: ActorRole) -> list[LiabilityMapping]:
        return [m for m in self.liability_mappings if m.actor == actor]

    def get_liabilities_by_attack(self, attack_class: str) -> list[LiabilityMapping]:
        return [m for m in self.liability_mappings if m.attack_class == attack_class]

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligations": [
                {
                    "id": o.obligation_id,
                    "description": o.description,
                    "actor": o.actor.value,
                    "controls": o.controls,
                    "regulatory_refs": o.regulatory_refs,
                    "verification": o.verification_method,
                }
                for o in self.obligations
            ],
            "liability_mappings": [
                {
                    "attack_class": m.attack_class,
                    "actor": m.actor.value,
                    "liability_type": m.liability_type.value,
                    "regulatory_basis": m.regulatory_basis,
                    "max_exposure": m.max_exposure,
                    "mitigation": m.mitigation,
                }
                for m in self.liability_mappings
            ],
        }


def build_default_model() -> SharedResponsibilityModel:
    model = SharedResponsibilityModel()

    model.obligations = [
        SecurityObligation(
            obligation_id="PD-001",
            description="Implement prompt hardening and agent sandboxing",
            actor=ActorRole.PLATFORM_DEVELOPER,
            controls=["Prompt boundary enforcement", "Tool call authorization", "Output filtering"],
            regulatory_refs=["EU AI Act Art. 15", "NIST AI RMF GOVERN-1"],
            verification_method="Red-team evaluation per MCPoisoner test matrix",
        ),
        SecurityObligation(
            obligation_id="PD-002",
            description="Operate coordinated vulnerability disclosure program",
            actor=ActorRole.PLATFORM_DEVELOPER,
            controls=["CVD policy", "90-day disclosure timeline", "Security advisories"],
            regulatory_refs=["EU AI Act Art. 62", "NIST CSF RS.AN"],
            verification_method="Published CVD policy with response SLA metrics",
        ),
        SecurityObligation(
            obligation_id="SP-001",
            description="Sign all tool descriptions with Ed25519 via CryptoMCP",
            actor=ActorRole.SERVER_PUBLISHER,
            controls=["Ed25519 signing", "SHA-256 integrity", "Trust Registry enrollment"],
            regulatory_refs=["SOC 2 CC6.1", "ISO 27001 A.10.1"],
            verification_method="CryptoMCP signature verification on every tool load",
        ),
        SecurityObligation(
            obligation_id="SP-002",
            description="Declare tool capabilities honestly and completely",
            actor=ActorRole.SERVER_PUBLISHER,
            controls=["Capability declaration", "Schema accuracy", "Permission scoping"],
            regulatory_refs=["FTC Act § 5", "EU AI Act Art. 13"],
            verification_method="MCPShield static analysis + manual audit",
        ),
        SecurityObligation(
            obligation_id="ED-001",
            description="Deploy MCPShield for all production MCP tool integrations",
            actor=ActorRole.ENTERPRISE_DEPLOYER,
            controls=["MCPShield proxy", "Policy engine", "Runtime monitoring", "Audit logging"],
            regulatory_refs=["GDPR Art. 32", "SOC 2 CC6", "NIST CSF PR.DS"],
            verification_method="MCPShield deployment verification + audit log review",
        ),
        SecurityObligation(
            obligation_id="ED-002",
            description="Maintain MCP incident response plan",
            actor=ActorRole.ENTERPRISE_DEPLOYER,
            controls=["IR playbook", "Detection rules", "Notification procedures", "Forensics"],
            regulatory_refs=["GDPR Art. 33-34", "NIST CSF RS", "SOC 2 CC7"],
            verification_method="Annual IR tabletop exercise with MCP attack scenarios",
        ),
        SecurityObligation(
            obligation_id="EU-001",
            description="Informed consent for AI agent tool use",
            actor=ActorRole.END_USER,
            controls=["Consent flow", "Tool visibility", "Opt-out mechanism"],
            regulatory_refs=["GDPR Art. 7", "EU AI Act Art. 52"],
            verification_method="UX audit of consent flow completeness",
        ),
    ]

    model.liability_mappings = [
        LiabilityMapping(
            attack_class="description_injection",
            actor=ActorRole.PLATFORM_DEVELOPER,
            liability_type=LiabilityType.PRODUCT_LIABILITY,
            regulatory_basis="EU AI Act Art. 15 — Failure to ensure robustness",
            max_exposure="€15M or 3% annual turnover",
            mitigation="Implement CryptoMCP signature verification in agent runtime",
        ),
        LiabilityMapping(
            attack_class="description_injection",
            actor=ActorRole.SERVER_PUBLISHER,
            liability_type=LiabilityType.FRAUD,
            regulatory_basis="FTC Act § 5 — Deceptive tool description",
            max_exposure="FTC enforcement action + civil penalties",
            mitigation="CryptoMCP signing + honest capability declaration",
        ),
        LiabilityMapping(
            attack_class="tool_shadowing",
            actor=ActorRole.PLATFORM_DEVELOPER,
            liability_type=LiabilityType.PRODUCT_LIABILITY,
            regulatory_basis="EU AI Act Art. 15 — Cybersecurity requirement",
            max_exposure="€15M or 3% annual turnover",
            mitigation="PKI-based publisher authentication via CryptoMCP",
        ),
        LiabilityMapping(
            attack_class="rug_pull",
            actor=ActorRole.SERVER_PUBLISHER,
            liability_type=LiabilityType.FRAUD,
            regulatory_basis="Contract law — Breach of declared capabilities",
            max_exposure="Contract damages + regulatory penalties",
            mitigation="Hash baseline verification via CryptoMCP",
        ),
        LiabilityMapping(
            attack_class="return_value_poisoning",
            actor=ActorRole.ENTERPRISE_DEPLOYER,
            liability_type=LiabilityType.DATA_CONTROLLER,
            regulatory_basis="GDPR Art. 5(1)(f) — Integrity and confidentiality",
            max_exposure="€20M or 4% annual turnover",
            mitigation="MCPShield runtime monitoring + output validation",
        ),
        LiabilityMapping(
            attack_class="cross_tool_escalation",
            actor=ActorRole.ENTERPRISE_DEPLOYER,
            liability_type=LiabilityType.NEGLIGENCE,
            regulatory_basis="NIST CSF PR.AC — Access control",
            max_exposure="Breach damages + regulatory fines",
            mitigation="MCPShield policy engine + data flow tracking",
        ),
    ]

    return model
