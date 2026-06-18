"""Defense simulation engine — runs attacks through all defense layers."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpoisoner.attacks.base import AttackClass, AttackConfig, BaseAttack
from mcpshield.static_analysis.scanner import StaticScanner, ScanResult, ThreatLevel
from mcpshield.runtime_monitor.monitor import (
    RuntimeMonitor,
    MonitorDecision,
    ToolInvocation,
)
from mcpshield.policy_engine.engine import (
    PolicyEngine,
    PolicyDecision,
    PolicyRule,
    PolicyAction,
)
from cryptomcp.signing.signer import ToolSigner, ToolVerifier, compute_tool_hash
from cryptomcp.signing.keys import generate_key_pair
from cryptomcp.merkle.audit_log import MerkleAuditLog

logger = structlog.get_logger()


@dataclass
class SimulationResult:
    """Result of running one attack variant through the defense stack."""

    attack_name: str
    attack_variant: str
    layers_triggered: list[str]
    passed_through: bool
    detection_time_ms: float
    findings: list[str]
    recommendations: list[str]
    static_scan_result: ScanResult | None = None
    runtime_decision: MonitorDecision | None = None
    policy_decision: PolicyDecision | None = None
    crypto_valid: bool | None = None
    audit_entry_hash: str = ""


@dataclass
class MatrixResult:
    """Aggregate results from a full attack-matrix simulation."""

    results: list[SimulationResult] = field(default_factory=list)
    total_attacks: int = 0
    total_blocked: int = 0
    total_passed: int = 0
    layer_detection_counts: dict[str, int] = field(default_factory=dict)

    @property
    def block_rate(self) -> float:
        return self.total_blocked / self.total_attacks if self.total_attacks else 0.0


@dataclass
class RedVsBlueResult:
    """Result of a red-team vs blue-team simulation."""

    red_team_score: int = 0
    blue_team_score: int = 0
    rounds: list[SimulationResult] = field(default_factory=list)
    winner: str = ""


# ---------------------------------------------------------------------------
# Default defense policy rules used when no external policy file is provided
# ---------------------------------------------------------------------------

_DEFAULT_POLICY_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="block_malicious_tags",
        description="Block any tool tagged as malicious",
        condition={"has_tag": "malicious"},
        action=PolicyAction.BLOCK,
        compliance_refs=["NIST CSF PR.AC", "OWASP LLM03"],
        priority=100,
    ),
    PolicyRule(
        rule_id="block_network_exfil",
        description="Block tools requesting network + exfiltration capabilities",
        condition={"requires_capability": "network_exfil"},
        action=PolicyAction.BLOCK,
        compliance_refs=["GDPR Art. 5(1)(f)"],
        priority=90,
    ),
    PolicyRule(
        rule_id="approve_sensitive_data",
        description="Require approval for tools accessing sensitive data",
        condition={"data_classification": "sensitive"},
        action=PolicyAction.REQUEST_APPROVAL,
        compliance_refs=["GDPR Art. 35", "NIST CSF PR.DS"],
        priority=80,
    ),
]


class DefenseSimulator:
    """Orchestrates attack payloads through the full MCPShield + CryptoMCP stack."""

    def __init__(
        self,
        static_scanner: StaticScanner | None = None,
        runtime_monitor: RuntimeMonitor | None = None,
        policy_engine: PolicyEngine | None = None,
        enable_crypto: bool = True,
    ) -> None:
        self.scanner = static_scanner or StaticScanner()
        self.monitor = runtime_monitor or RuntimeMonitor()
        self.policy = policy_engine or self._default_policy_engine()
        self.enable_crypto = enable_crypto
        self.audit_log = MerkleAuditLog()
        self.log = logger.bind(component="defense_simulator")

        # Crypto artefacts — generated once per simulator instance
        if self.enable_crypto:
            self._key_pair = generate_key_pair()
            self._signer = ToolSigner(self._key_pair, publisher_id="defense_lab")
            self._verifier = ToolVerifier()
        else:
            self._key_pair = None
            self._signer = None
            self._verifier = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_simulation(
        self,
        attack_type: str,
        variant: str = "default",
        defense_config: dict[str, Any] | None = None,
    ) -> SimulationResult:
        """Run a single attack variant through all defense layers."""
        cfg = defense_config or {}
        attack_cls = ATTACK_REGISTRY.get(attack_type)
        if attack_cls is None:
            raise ValueError(
                f"Unknown attack type '{attack_type}'. "
                f"Available: {list(ATTACK_REGISTRY)}"
            )

        attack_config = AttackConfig(
            attack_class=AttackClass(attack_type),
            llm_backend=cfg.get("llm_backend", "simulated"),
            agent_framework=cfg.get("agent_framework", "simulated"),
            payload_variant=variant,
        )
        attack_instance: BaseAttack = attack_cls(attack_config)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                payload = pool.submit(
                    asyncio.run, attack_instance.prepare_payload()
                ).result()
        else:
            payload = asyncio.run(attack_instance.prepare_payload())

        return self._evaluate_payload(attack_type, variant, payload, attack_instance)

    def run_full_matrix(self) -> MatrixResult:
        """Test every attack type x variant against all defense layers."""
        matrix = MatrixResult()
        variant_map = self._build_variant_map()

        for attack_type, variants in variant_map.items():
            for variant in variants:
                result = self.run_simulation(attack_type, variant)
                matrix.results.append(result)
                matrix.total_attacks += 1
                if not result.passed_through:
                    matrix.total_blocked += 1
                else:
                    matrix.total_passed += 1
                for layer in result.layers_triggered:
                    matrix.layer_detection_counts[layer] = (
                        matrix.layer_detection_counts.get(layer, 0) + 1
                    )

        return matrix

    def run_red_vs_blue(
        self,
        attack_types: list[str] | None = None,
        evasion_level: int = 1,
    ) -> RedVsBlueResult:
        """Simulate red team (attacker) vs blue team (defender)."""
        attack_types = attack_types or list(ATTACK_REGISTRY)
        variant_map = self._build_variant_map()
        result = RedVsBlueResult()

        for attack_type in attack_types:
            variants = variant_map.get(attack_type, ["default"])
            # Red team picks up to `evasion_level` variants per attack type
            chosen = variants[:evasion_level] if evasion_level <= len(variants) else variants
            for variant in chosen:
                sim = self.run_simulation(attack_type, variant)
                result.rounds.append(sim)
                if sim.passed_through:
                    result.red_team_score += 1
                else:
                    result.blue_team_score += 1

        result.winner = (
            "blue_team" if result.blue_team_score >= result.red_team_score else "red_team"
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_payload(
        self,
        attack_type: str,
        variant: str,
        payload: dict[str, Any],
        attack_instance: BaseAttack,
    ) -> SimulationResult:
        start = time.monotonic()
        layers_triggered: list[str] = []
        findings: list[str] = []
        recommendations: list[str] = []

        # Build a tool descriptor from the payload
        tool_descriptor = self._extract_tool_descriptor(payload)

        # --- Layer 1: Static analysis ---
        scan_result = self.scanner.scan(tool_descriptor)
        if not scan_result.is_safe:
            layers_triggered.append("static_scanner")
            for f in scan_result.findings:
                findings.append(f"[Static] {f.description}")
                recommendations.append(f"[Static] {f.recommendation}")

        # --- Layer 2: Runtime monitor ---
        invocation = ToolInvocation(
            tool_name=tool_descriptor.get("name", "unknown"),
            timestamp=time.time(),
            input_data=tool_descriptor.get("inputSchema", {}),
            output_data=None,
            caller_context="defense_lab_simulation",
            session_id="sim_session",
        )
        runtime_decision = self.monitor.record_invocation(invocation)
        if runtime_decision != MonitorDecision.ALLOW:
            layers_triggered.append("runtime_monitor")
            findings.append(f"[Runtime] Decision: {runtime_decision.value}")
            recommendations.append("[Runtime] Review behavioral anomalies")

        # --- Layer 3: Policy engine ---
        tags = self._infer_tags(scan_result)
        capabilities = self._infer_capabilities(payload)
        data_classifications = self._infer_data_classifications(payload)
        policy_eval = self.policy.evaluate(
            tool_name=tool_descriptor.get("name", "unknown"),
            tool_tags=tags,
            requested_capabilities=capabilities,
            data_classifications=data_classifications,
        )
        if policy_eval.decision != PolicyDecision.ALLOW:
            layers_triggered.append("policy_engine")
            findings.append(f"[Policy] {policy_eval.explanation}")
            for ref in policy_eval.compliance_evidence:
                recommendations.append(f"[Policy] Compliance: {ref}")

        # --- Layer 4: Crypto verification ---
        crypto_valid: bool | None = None
        if self.enable_crypto and self._signer and self._verifier:
            signed = self._signer.sign(tool_descriptor)
            verification = self._verifier.verify(signed)
            crypto_valid = verification.valid

            # Now simulate tampering: re-sign with mutated descriptor
            mutated = self._extract_mutated_descriptor(payload, tool_descriptor)
            if mutated != tool_descriptor:
                tampered_signed = self._signer.sign(tool_descriptor)
                # Replace tool in-place to simulate rug-pull
                object.__setattr__(tampered_signed, "tool", mutated)
                object.__setattr__(
                    tampered_signed,
                    "tool_hash",
                    tampered_signed.tool_hash,  # keep original hash
                )
                tamper_result = self._verifier.verify(tampered_signed)
                if not tamper_result.valid:
                    layers_triggered.append("crypto_verification")
                    findings.append(
                        f"[Crypto] Tamper detected: {tamper_result.error}"
                    )
                    recommendations.append(
                        "[Crypto] Reject tool — signature/hash mismatch after mutation"
                    )

        # --- Audit log entry ---
        tool_hash = compute_tool_hash(tool_descriptor)
        audit_decision = "blocked" if layers_triggered else "allowed"
        entry = self.audit_log.append(
            tool_name=tool_descriptor.get("name", "unknown"),
            tool_hash=tool_hash,
            action=f"simulate_{attack_type}_{variant}",
            decision=audit_decision,
            metadata={"layers_triggered": layers_triggered},
        )

        elapsed_ms = (time.monotonic() - start) * 1000
        passed_through = len(layers_triggered) == 0

        return SimulationResult(
            attack_name=attack_type,
            attack_variant=variant,
            layers_triggered=layers_triggered,
            passed_through=passed_through,
            detection_time_ms=round(elapsed_ms, 3),
            findings=findings,
            recommendations=recommendations,
            static_scan_result=scan_result,
            runtime_decision=runtime_decision,
            policy_decision=policy_eval.decision,
            crypto_valid=crypto_valid,
            audit_entry_hash=entry.entry_hash,
        )

    def _extract_tool_descriptor(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Pull a tool descriptor dict out of various attack payload shapes."""
        # Description injection / rug-pull payloads
        if "poisoned_description" in payload:
            return {
                "name": payload.get("tool_name", "unknown"),
                "description": payload["poisoned_description"],
                "inputSchema": payload.get("parameters", {}),
            }
        if "mutated_tool" in payload:
            return payload["mutated_tool"]
        if "shadow_tool" in payload:
            return payload["shadow_tool"]
        # Generic: try to find a tool-shaped dict
        for key in ("tool", "tool_descriptor", "malicious_tool"):
            if key in payload and isinstance(payload[key], dict):
                return payload[key]
        # Fallback: treat the whole payload as a tool descriptor
        return {
            "name": payload.get("tool_name", payload.get("name", "unknown")),
            "description": payload.get("description", str(payload)[:500]),
            "inputSchema": payload.get("inputSchema", {}),
        }

    def _extract_mutated_descriptor(
        self,
        payload: dict[str, Any],
        original: dict[str, Any],
    ) -> dict[str, Any]:
        """If the payload contains a pre/post mutation pair, return the mutated one."""
        if "mutated_tool" in payload and "benign_tool" in payload:
            return payload["mutated_tool"]
        return original

    def _infer_tags(self, scan_result: ScanResult) -> list[str]:
        tags: list[str] = []
        if scan_result.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.BLOCKED):
            tags.append("malicious")
        if scan_result.threat_level == ThreatLevel.SUSPICIOUS:
            tags.append("suspicious")
        return tags

    def _infer_capabilities(self, payload: dict[str, Any]) -> list[str]:
        caps: list[str] = []
        text = str(payload).lower()
        if "exfil" in text or "attacker" in text:
            caps.append("network_exfil")
        if "execute" in text or "shell" in text:
            caps.append("code_execution")
        if "filesystem" in text or "write_file" in text:
            caps.append("filesystem_write")
        return caps

    def _infer_data_classifications(self, payload: dict[str, Any]) -> list[str]:
        classes: list[str] = []
        text = str(payload).lower()
        if any(kw in text for kw in ("secret", "credential", "api_key", "password")):
            classes.append("sensitive")
        if any(kw in text for kw in ("pii", "email", "ssn")):
            classes.append("pii")
        return classes

    def _build_variant_map(self) -> dict[str, list[str]]:
        """Return known variants for each attack type."""
        from mcpoisoner.attacks.description_injection import DescriptionInjectionAttack
        from mcpoisoner.attacks.tool_shadowing import ToolShadowingAttack

        variant_map: dict[str, list[str]] = {}

        if hasattr(DescriptionInjectionAttack, "INJECTION_VARIANTS"):
            variant_map["description_injection"] = list(
                DescriptionInjectionAttack.INJECTION_VARIANTS.keys()
            )
        else:
            variant_map["description_injection"] = ["default"]

        if hasattr(ToolShadowingAttack, "SHADOW_STRATEGIES"):
            variant_map["tool_shadowing"] = list(
                ToolShadowingAttack.SHADOW_STRATEGIES.keys()
            )
        else:
            variant_map["tool_shadowing"] = ["default"]

        variant_map.setdefault(
            "rug_pull",
            ["description_swap", "parameter_injection", "capability_escalation"],
        )
        variant_map.setdefault(
            "return_value_poisoning",
            ["default"],
        )
        variant_map.setdefault(
            "cross_tool_escalation",
            ["default"],
        )

        return variant_map

    @staticmethod
    def _default_policy_engine() -> PolicyEngine:
        engine = PolicyEngine()
        for rule in _DEFAULT_POLICY_RULES:
            engine.add_rule(rule)
        return engine
