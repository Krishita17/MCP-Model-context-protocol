"""MCP JSON-RPC proxy that integrates all three MCPShield layers."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from cryptomcp.merkle.audit_log import MerkleAuditLog
from cryptomcp.signing.signer import SignedToolDescriptor, ToolVerifier
from mcpshield.static_analysis.scanner import StaticScanner, ThreatLevel
from mcpshield.runtime_monitor.monitor import (
    RuntimeMonitor,
    MonitorDecision,
    ToolInvocation,
)
from mcpshield.policy_engine.engine import PolicyEngine, PolicyDecision

logger = structlog.get_logger()


class InterceptionDecision:
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class InterceptionResult:
    decision: str
    tool_name: str
    layer_results: dict[str, Any] = field(default_factory=dict)
    audit_entry_hash: str | None = None
    timestamp: float = field(default_factory=time.time)


class MCPShieldProxy:
    """Unified proxy integrating static analysis, runtime monitoring, and policy enforcement."""

    def __init__(
        self,
        scanner: StaticScanner | None = None,
        monitor: RuntimeMonitor | None = None,
        policy_engine: PolicyEngine | None = None,
        verifier: ToolVerifier | None = None,
        audit_log: MerkleAuditLog | None = None,
    ) -> None:
        self.scanner = scanner or StaticScanner()
        self.monitor = monitor or RuntimeMonitor()
        self.policy_engine = policy_engine or PolicyEngine()
        self.verifier = verifier or ToolVerifier()
        self.audit_log = audit_log or MerkleAuditLog()
        self.approved_tools: dict[str, str] = {}
        self.log = logger.bind(component="mcpshield_proxy")

    def register_tool(
        self,
        tool_descriptor: dict[str, Any],
        signed_bundle: dict[str, Any] | None = None,
    ) -> InterceptionResult:
        tool_name = tool_descriptor.get("name", "unknown")
        layer_results: dict[str, Any] = {}

        if signed_bundle:
            descriptor = SignedToolDescriptor.from_bundle(signed_bundle)
            verification = self.verifier.verify(descriptor)
            layer_results["crypto_verification"] = {
                "valid": verification.valid,
                "hash_matches": verification.hash_matches,
                "signature_valid": verification.signature_valid,
                "error": verification.error,
            }
            if not verification.valid:
                entry = self.audit_log.append(
                    tool_name=tool_name,
                    tool_hash=descriptor.tool_hash,
                    action="register",
                    decision="blocked_crypto",
                    metadata={"error": verification.error},
                )
                return InterceptionResult(
                    decision=InterceptionDecision.BLOCK,
                    tool_name=tool_name,
                    layer_results=layer_results,
                    audit_entry_hash=entry.entry_hash,
                )

        scan_result = self.scanner.scan(tool_descriptor)
        layer_results["static_analysis"] = {
            "threat_level": scan_result.threat_level.value,
            "findings": scan_result.finding_count,
            "score": scan_result.score,
        }

        if scan_result.threat_level == ThreatLevel.BLOCKED:
            entry = self.audit_log.append(
                tool_name=tool_name,
                tool_hash="",
                action="register",
                decision="blocked_static",
            )
            return InterceptionResult(
                decision=InterceptionDecision.BLOCK,
                tool_name=tool_name,
                layer_results=layer_results,
                audit_entry_hash=entry.entry_hash,
            )

        if scan_result.threat_level == ThreatLevel.SUSPICIOUS:
            entry = self.audit_log.append(
                tool_name=tool_name,
                tool_hash="",
                action="register",
                decision="requires_approval",
            )
            return InterceptionResult(
                decision=InterceptionDecision.REQUIRE_APPROVAL,
                tool_name=tool_name,
                layer_results=layer_results,
                audit_entry_hash=entry.entry_hash,
            )

        self.approved_tools[tool_name] = "approved"
        entry = self.audit_log.append(
            tool_name=tool_name,
            tool_hash="",
            action="register",
            decision="approved",
        )

        return InterceptionResult(
            decision=InterceptionDecision.ALLOW,
            tool_name=tool_name,
            layer_results=layer_results,
            audit_entry_hash=entry.entry_hash,
        )

    def intercept_invocation(
        self,
        tool_name: str,
        input_data: dict[str, Any],
        session_id: str = "",
    ) -> InterceptionResult:
        layer_results: dict[str, Any] = {}

        invocation = ToolInvocation(
            tool_name=tool_name,
            timestamp=time.time(),
            input_data=input_data,
            session_id=session_id,
        )
        monitor_decision = self.monitor.record_invocation(invocation)
        layer_results["runtime_monitor"] = {"decision": monitor_decision.value}

        if monitor_decision == MonitorDecision.BLOCK:
            entry = self.audit_log.append(
                tool_name=tool_name,
                tool_hash="",
                action="invoke",
                decision="blocked_runtime",
            )
            return InterceptionResult(
                decision=InterceptionDecision.BLOCK,
                tool_name=tool_name,
                layer_results=layer_results,
                audit_entry_hash=entry.entry_hash,
            )

        policy_eval = self.policy_engine.evaluate(
            tool_name=tool_name,
            tool_tags=[],
            requested_capabilities=[],
            data_classifications=[],
        )
        layer_results["policy_engine"] = {
            "decision": policy_eval.decision.value,
            "matched_rules": len(policy_eval.matched_rules),
            "explanation": policy_eval.explanation,
        }

        if policy_eval.decision == PolicyDecision.DENY:
            entry = self.audit_log.append(
                tool_name=tool_name,
                tool_hash="",
                action="invoke",
                decision="blocked_policy",
            )
            return InterceptionResult(
                decision=InterceptionDecision.BLOCK,
                tool_name=tool_name,
                layer_results=layer_results,
                audit_entry_hash=entry.entry_hash,
            )

        if (
            policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
            or monitor_decision == MonitorDecision.ESCALATE
        ):
            entry = self.audit_log.append(
                tool_name=tool_name,
                tool_hash="",
                action="invoke",
                decision="requires_approval",
            )
            return InterceptionResult(
                decision=InterceptionDecision.REQUIRE_APPROVAL,
                tool_name=tool_name,
                layer_results=layer_results,
                audit_entry_hash=entry.entry_hash,
            )

        entry = self.audit_log.append(
            tool_name=tool_name,
            tool_hash="",
            action="invoke",
            decision="allowed",
        )
        return InterceptionResult(
            decision=InterceptionDecision.ALLOW,
            tool_name=tool_name,
            layer_results=layer_results,
            audit_entry_hash=entry.entry_hash,
        )
