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
from mcpoisoner.backends import available_backends, is_backend_available
from mcpoisoner.results.writer import write_run_result, write_aggregate_csv

logger = structlog.get_logger()

LLM_BACKENDS = ["gpt-4o", "claude-sonnet", "gemini-2.5", "llama-3.1-8b"]
AGENT_FRAMEWORKS = ["langchain", "crewai", "autogen"]
ATTACK_CLASSES = list(AttackClass)


@dataclass
class MatrixConfig:
    llm_backends: list[str] = field(default_factory=lambda: LLM_BACKENDS.copy())
    agent_frameworks: list[str] = field(default_factory=lambda: AGENT_FRAMEWORKS.copy())
    attack_classes: list[AttackClass] = field(default_factory=lambda: ATTACK_CLASSES.copy())
    iterations_per_config: int = 10
    timeout_seconds: float = 60.0
    temperature: float = 0.0
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
    skipped_backends: list[str] = field(default_factory=list)
    error_count: int = 0
    valid_attacks: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def overall_asr(self) -> float:
        # ASR over runs that produced a real outcome (errored runs excluded).
        denom = self.valid_attacks or self.total_attacks
        if denom == 0:
            return 0.0
        return self.successful_attacks / denom

    def summary(self) -> dict[str, Any]:
        return {
            "total_configurations": self.total_configs,
            "completed": self.completed_configs,
            "overall_attack_success_rate": round(self.overall_asr, 4),
            "execution_time_seconds": round(self.execution_time_seconds, 2),
            "skipped_backends": self.skipped_backends,
            "errors": self.error_count,
            "by_attack_class": {
                k: {
                    "total": len(v),
                    "valid": sum(1 for r in v if r.success is not None),
                    "successful": sum(1 for r in v if r.success is True),
                    "asr": round(
                        sum(1 for r in v if r.success is True)
                        / max(sum(1 for r in v if r.success is not None), 1),
                        4,
                    ),
                }
                for k, v in self.results_by_attack.items()
            },
            "by_llm_backend": {
                k: {
                    "total": len(v),
                    "valid": sum(1 for r in v if r.success is not None),
                    "successful": sum(1 for r in v if r.success is True),
                    "asr": round(
                        sum(1 for r in v if r.success is True)
                        / max(sum(1 for r in v if r.success is not None), 1),
                        4,
                    ),
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
                            temperature=self.config.temperature,
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

        # Filter to available backends
        avail = set(available_backends())
        skipped: list[str] = []
        active_backends: list[str] = []
        for b in self.config.llm_backends:
            if is_backend_available(b):
                active_backends.append(b)
            else:
                skipped.append(b)
                self.log.warning("skipping_backend", backend=b, reason="API key not configured")

        self.config.llm_backends = active_backends

        if not active_backends:
            self.log.error("no_backends_available")
            return MatrixResult(
                total_configs=0,
                completed_configs=0,
                total_attacks=0,
                successful_attacks=0,
                results_by_attack={},
                results_by_llm={},
                results_by_framework={},
                execution_time_seconds=0,
                skipped_backends=skipped,
            )

        configs = self.generate_configs()
        self.log.info(
            "starting_attack_matrix",
            total_configs=len(configs),
            backends=active_backends,
            skipped=skipped,
        )

        all_results: list[AttackResult] = []
        semaphore = asyncio.Semaphore(self.config.parallel_configs)

        async def run_with_semaphore(cfg: AttackConfig) -> list[AttackResult]:
            async with semaphore:
                return await self.run_single_config(cfg)

        tasks = [run_with_semaphore(cfg) for cfg in configs]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        completed = 0
        error_count = 0
        for i, batch in enumerate(batch_results):
            if isinstance(batch, list):
                # Save per-run JSON for each result
                for j, r in enumerate(batch):
                    r.iteration = j + 1
                    try:
                        write_run_result(r, self.config.output_dir, iteration=j + 1)
                    except Exception as e:
                        self.log.warning("result_write_failed", error=str(e))
                all_results.extend(batch)
                completed += 1
            else:
                error_count += 1
                self.log.error("config_exception", error=str(batch))

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
            successful_attacks=sum(1 for r in all_results if r.success is True),
            valid_attacks=sum(1 for r in all_results if r.success is not None),
            results_by_attack=results_by_attack,
            results_by_llm=results_by_llm,
            results_by_framework=results_by_framework,
            execution_time_seconds=elapsed,
            skipped_backends=skipped,
            error_count=error_count,
        )

        self.log.info("matrix_complete", summary=matrix_result.summary())

        # Write aggregate CSV
        try:
            csv_path = write_aggregate_csv(all_results, self.config.output_dir)
            self.log.info("aggregate_csv_saved", path=str(csv_path))
        except Exception as e:
            self.log.warning("csv_write_failed", error=str(e))

        return matrix_result

    async def save_results(self, result: MatrixResult, output_dir: Path | None = None) -> Path:
        out = output_dir or self.config.output_dir
        out.mkdir(parents=True, exist_ok=True)
        filepath = out / f"matrix_results_{int(result.timestamp)}.json"
        filepath.write_text(json.dumps(result.summary(), indent=2))
        self.log.info("results_saved", path=str(filepath))
        return filepath
