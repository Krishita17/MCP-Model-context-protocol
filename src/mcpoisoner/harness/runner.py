"""Attack harness runner for executing the full 60-config test matrix."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpoisoner.attacks.base import AttackConfig, AttackClass, AttackResult

logger = structlog.get_logger()

LLM_BACKENDS = ["gpt-4o", "claude-sonnet", "gemini-2.5", "llama-3.1-70b"]
AGENT_FRAMEWORKS = ["langchain", "crewai", "autogen"]
ATTACK_CLASSES = list(AttackClass)


@dataclass
class MatrixConfig:
    llm_backends: list[str] = field(default_factory=lambda: LLM_BACKENDS.copy())
    agent_frameworks: list[str] = field(default_factory=lambda: AGENT_FRAMEWORKS.copy())
    attack_classes: list[AttackClass] = field(default_factory=lambda: ATTACK_CLASSES.copy())
    iterations_per_config: int = 10
    timeout_seconds: float = 30.0
    output_dir: Path = Path("results")
    parallel_configs: int = 4


@dataclass
class MatrixResult:
    total_configs: int
    completed_configs: int
    total_attacks: int
    successful_attacks: int
    results_by_attack: dict[str, list[AttackResult]]
    results_by_llm: dict[str, list[AttackResult]]
    results_by_framework: dict[str, list[AttackResult]]
    execution_time_seconds: float
    timestamp: float = field(default_factory=time.time)

    @property
    def overall_asr(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return self.successful_attacks / self.total_attacks

    def summary(self) -> dict[str, Any]:
        return {
            "total_configurations": self.total_configs,
            "completed": self.completed_configs,
            "overall_attack_success_rate": round(self.overall_asr, 4),
            "execution_time_seconds": round(self.execution_time_seconds, 2),
            "by_attack_class": {
                k: {
                    "total": len(v),
                    "successful": sum(1 for r in v if r.success),
                    "asr": round(sum(1 for r in v if r.success) / max(len(v), 1), 4),
                }
                for k, v in self.results_by_attack.items()
            },
            "by_llm_backend": {
                k: {
                    "total": len(v),
                    "successful": sum(1 for r in v if r.success),
                    "asr": round(sum(1 for r in v if r.success) / max(len(v), 1), 4),
                }
                for k, v in self.results_by_llm.items()
            },
        }


class AttackMatrixRunner:
    def __init__(self, config: MatrixConfig | None = None) -> None:
        self.config = config or MatrixConfig()
        self.log = logger.bind(component="attack_matrix")

    def generate_configs(self) -> list[AttackConfig]:
        configs: list[AttackConfig] = []
        for attack_class in self.config.attack_classes:
            for llm in self.config.llm_backends:
                for framework in self.config.agent_frameworks:
                    configs.append(
                        AttackConfig(
                            attack_class=attack_class,
                            llm_backend=llm,
                            agent_framework=framework,
                            iterations=self.config.iterations_per_config,
                            timeout_seconds=self.config.timeout_seconds,
                        )
                    )
        return configs

    async def run_single_config(self, config: AttackConfig) -> list[AttackResult]:
        attack_cls = ATTACK_REGISTRY.get(config.attack_class.value)
        if attack_cls is None:
            self.log.error("unknown_attack_class", attack_class=config.attack_class)
            return []

        attack = attack_cls(config)
        try:
            return await asyncio.wait_for(
                attack.run(),
                timeout=config.timeout_seconds * config.iterations,
            )
        except asyncio.TimeoutError:
            self.log.warning("config_timeout", config=str(config))
            return []

    async def run_matrix(self) -> MatrixResult:
        start_time = time.monotonic()
        configs = self.generate_configs()
        self.log.info("starting_attack_matrix", total_configs=len(configs))

        all_results: list[AttackResult] = []
        semaphore = asyncio.Semaphore(self.config.parallel_configs)

        async def run_with_semaphore(cfg: AttackConfig) -> list[AttackResult]:
            async with semaphore:
                return await self.run_single_config(cfg)

        tasks = [run_with_semaphore(cfg) for cfg in configs]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        completed = 0
        for batch in batch_results:
            if isinstance(batch, list):
                all_results.extend(batch)
                completed += 1

        results_by_attack: dict[str, list[AttackResult]] = {}
        results_by_llm: dict[str, list[AttackResult]] = {}
        results_by_framework: dict[str, list[AttackResult]] = {}

        for r in all_results:
            results_by_attack.setdefault(r.attack_class.value, []).append(r)
            results_by_llm.setdefault(r.llm_backend, []).append(r)
            results_by_framework.setdefault(r.agent_framework, []).append(r)

        elapsed = time.monotonic() - start_time

        matrix_result = MatrixResult(
            total_configs=len(configs),
            completed_configs=completed,
            total_attacks=len(all_results),
            successful_attacks=sum(1 for r in all_results if r.success),
            results_by_attack=results_by_attack,
            results_by_llm=results_by_llm,
            results_by_framework=results_by_framework,
            execution_time_seconds=elapsed,
        )

        self.log.info("matrix_complete", summary=matrix_result.summary())
        return matrix_result

    async def save_results(self, result: MatrixResult, output_dir: Path | None = None) -> Path:
        out = output_dir or self.config.output_dir
        out.mkdir(parents=True, exist_ok=True)
        filepath = out / f"matrix_results_{int(result.timestamp)}.json"
        filepath.write_text(json.dumps(result.summary(), indent=2))
        self.log.info("results_saved", path=str(filepath))
        return filepath
