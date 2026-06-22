"""Base attack class defining the interface for all MCP attack implementations."""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AttackClass(str, Enum):
    DESCRIPTION_INJECTION = "description_injection"
    TOOL_SHADOWING = "tool_shadowing"
    RUG_PULL = "rug_pull"
    RETURN_VALUE_POISONING = "return_value_poisoning"
    CROSS_TOOL_ESCALATION = "cross_tool_escalation"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackResult:
    attack_class: AttackClass
    # None = unknown (the LLM call errored, so we cannot say the attack
    # succeeded or failed). True/False are only set from observed LLM behavior.
    success: bool | None
    attack_success_rate: float
    time_to_detection_ms: float | None
    data_exfiltration_bytes: int
    regulatory_triggers: list[str]
    crypto_defense_effective: bool | None
    details: dict[str, Any] = field(default_factory=dict)
    llm_backend: str = ""
    agent_framework: str = ""
    timestamp: float = field(default_factory=time.time)
    llm_raw_output: str = ""
    error: str | None = None
    iteration: int = 0

    @property
    def regulatory_trigger_rate(self) -> float:
        return 1.0 if self.regulatory_triggers else 0.0


@dataclass
class AttackConfig:
    attack_class: AttackClass
    llm_backend: str
    agent_framework: str
    payload_variant: str = "default"
    iterations: int = 10
    timeout_seconds: float = 30.0
    # Sampling temperature for the LLM. 0.0 = deterministic (identical output
    # every iteration). Use >0 (e.g. 0.7) so each iteration is an independent
    # sample and the attack-success-rate reflects real run-to-run variation.
    temperature: float = 0.0
    custom_params: dict[str, Any] = field(default_factory=dict)


class BaseAttack(ABC):
    """Abstract base for all MCP attack implementations."""

    attack_class: AttackClass
    severity: Severity
    description: str
    mitre_atlas_id: str
    owasp_mapping: str
    crypto_exploitability: str

    def __init__(self, config: AttackConfig) -> None:
        self.config = config
        self.log = logger.bind(
            attack_class=self.attack_class.value,
            llm_backend=config.llm_backend,
            agent_framework=config.agent_framework,
        )

    @abstractmethod
    async def prepare_payload(self) -> dict[str, Any]:
        """Construct the attack payload (malicious tool description, return value, etc.)."""

    @abstractmethod
    async def execute(self) -> AttackResult:
        """Execute the attack against the target configuration."""

    @abstractmethod
    async def verify_impact(self, result: AttackResult) -> AttackResult:
        """Verify whether the attack achieved its objective."""

    @abstractmethod
    def get_regulatory_triggers(self) -> list[str]:
        """Return list of regulatory articles this attack could trigger."""

    def _check_mcpshield(self, tool_descriptor: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Run MCPShield on a tool descriptor. Returns (blocked, info_dict)."""
        try:
            from mcpshield.proxy.interceptor import MCPShieldProxy, InterceptionDecision

            proxy = MCPShieldProxy()
            result = proxy.register_tool(tool_descriptor)
            blocked = result.decision == InterceptionDecision.BLOCK
            layer = None
            if blocked:
                lr = result.layer_results
                if "crypto_verification" in lr and not lr["crypto_verification"].get("valid", True):
                    layer = "crypto"
                elif "static_analysis" in lr and lr["static_analysis"].get("threat_level") == "blocked":
                    layer = "static"
                elif "runtime_monitor" in lr and lr["runtime_monitor"].get("decision") == "block":
                    layer = "runtime"
                elif "policy_engine" in lr and lr["policy_engine"].get("decision") == "deny":
                    layer = "policy"
            return blocked, {
                "mcpshield_blocked": blocked,
                "mcpshield_layer_triggered": layer,
                "mcpshield_details": result.layer_results,
            }
        except Exception as e:
            self.log.warning("mcpshield_check_failed", error=str(e))
            return False, {"mcpshield_blocked": False, "mcpshield_error": str(e)}

    async def _run_agent(self, tools: list, task: str):
        """Run a real LLM agent with the given ToolDefs and task string."""
        from mcpoisoner.frameworks import get_runner

        runner = get_runner(self.config.agent_framework)
        return await runner.run_with_retry(
            tools,
            task,
            self.config.llm_backend,
            temperature=self.config.temperature,
        )

    async def run(self) -> list[AttackResult]:
        results: list[AttackResult] = []

        # Hard-fail before any iteration if the target is Ollama and it is not
        # reachable — never silently record fake results for a dead backend.
        from mcpoisoner.backends import get_backend_config, verify_ollama_connection

        backend_cfg = get_backend_config(self.config.llm_backend)
        if backend_cfg["provider"] == "ollama":
            verify_ollama_connection(str(backend_cfg["model"]))

        for i in range(self.config.iterations):
            self.log.info("executing_attack_iteration", iteration=i + 1)
            try:
                result = await self.execute()
                result = await self.verify_impact(result)
                result.llm_backend = self.config.llm_backend
                result.agent_framework = self.config.agent_framework
                results.append(result)
            except Exception as e:
                # Strict mode (MCPOISONER_STRICT=1): crash loudly with the full
                # traceback instead of recording the error and continuing. Use
                # this during research to surface failed API calls immediately.
                if os.environ.get("MCPOISONER_STRICT"):
                    import traceback

                    print(
                        f"\n[STRICT] Attack iteration {i + 1} raised — halting.\n",
                        flush=True,
                    )
                    traceback.print_exc()
                    raise
                self.log.error("attack_iteration_failed", iteration=i + 1, error=str(e))
                results.append(
                    AttackResult(
                        attack_class=self.attack_class,
                        success=None,  # unknown — the run errored, not a real outcome
                        attack_success_rate=0.0,
                        time_to_detection_ms=None,
                        data_exfiltration_bytes=0,
                        regulatory_triggers=[],
                        crypto_defense_effective=None,
                        llm_backend=self.config.llm_backend,
                        agent_framework=self.config.agent_framework,
                        error=str(e),
                        details={"error": str(e)},
                    )
                )
        return results
