"""Base attack class defining the interface for all MCP attack implementations."""

from __future__ import annotations

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
    success: bool
    attack_success_rate: float
    time_to_detection_ms: float | None
    data_exfiltration_bytes: int
    regulatory_triggers: list[str]
    crypto_defense_effective: bool | None
    details: dict[str, Any] = field(default_factory=dict)
    llm_backend: str = ""
    agent_framework: str = ""
    timestamp: float = field(default_factory=time.time)

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

    async def run(self) -> list[AttackResult]:
        results: list[AttackResult] = []
        for i in range(self.config.iterations):
            self.log.info("executing_attack_iteration", iteration=i + 1)
            try:
                result = await self.execute()
                result = await self.verify_impact(result)
                result.llm_backend = self.config.llm_backend
                result.agent_framework = self.config.agent_framework
                results.append(result)
            except Exception as e:
                self.log.error("attack_iteration_failed", iteration=i + 1, error=str(e))
                results.append(
                    AttackResult(
                        attack_class=self.attack_class,
                        success=False,
                        attack_success_rate=0.0,
                        time_to_detection_ms=None,
                        data_exfiltration_bytes=0,
                        regulatory_triggers=[],
                        crypto_defense_effective=None,
                        details={"error": str(e)},
                    )
                )
        return results
