"""Base types and abstract runner for agent frameworks."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


@dataclass
class ToolDef:
    """Framework-agnostic tool definition."""

    name: str
    description: str
    func: Callable
    parameters: dict[str, Any] | None = None


@dataclass
class AgentExecutionResult:
    """Result of running an agent with tools."""

    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    final_output: str = ""
    raw_messages: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


class AgentRunner(ABC):
    """Abstract base for agent framework runners."""

    framework_name: str = "base"

    @abstractmethod
    async def run(
        self,
        tools: list[ToolDef],
        task: str,
        backend: str,
    ) -> AgentExecutionResult:
        """Run an agent with the given tools and task."""

    async def run_with_retry(
        self,
        tools: list[ToolDef],
        task: str,
        backend: str,
        max_retries: int = 3,
    ) -> AgentExecutionResult:
        import os

        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                return await self.run(tools, task, backend)
            except Exception as e:
                last_error = e
                # Strict mode: surface the real error (e.g. Ollama connection
                # refused, model not found) with a full traceback and re-raise.
                if os.environ.get("MCPOISONER_STRICT"):
                    import traceback

                    print(
                        f"\n[STRICT] {self.framework_name} agent call failed on "
                        f"backend '{backend}' — halting.\n",
                        flush=True,
                    )
                    traceback.print_exc()
                    raise
                err_str = str(e).lower()
                is_rate_limit = any(
                    kw in err_str
                    for kw in ("rate_limit", "rate limit", "429", "too many requests", "quota")
                )
                if is_rate_limit and attempt < max_retries:
                    wait = 2 ** (attempt + 1)
                    logger.warning(
                        "rate_limited_retrying",
                        attempt=attempt + 1,
                        wait_seconds=wait,
                        backend=backend,
                    )
                    await asyncio.sleep(wait)
                    continue
                break
        return AgentExecutionResult(error=str(last_error))
