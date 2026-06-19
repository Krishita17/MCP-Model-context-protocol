"""AutoGen agent runner — real LLM tool-calling agents."""

from __future__ import annotations

import asyncio
import inspect
import os
from typing import Any

import structlog

from mcpoisoner.backends import get_backend_config
from mcpoisoner.frameworks.base import AgentExecutionResult, AgentRunner, ToolDef

logger = structlog.get_logger()


class AutoGenRunner(AgentRunner):
    framework_name = "autogen"

    async def run(
        self,
        tools: list[ToolDef],
        task: str,
        backend: str,
    ) -> AgentExecutionResult:
        try:
            from autogen import AssistantAgent, UserProxyAgent, register_function
        except ImportError:
            return AgentExecutionResult(
                error="autogen not installed — run: pip install pyautogen"
            )

        config_list = self._create_config(backend)
        call_tracker: list[dict[str, Any]] = []

        assistant = AssistantAgent(
            name="assistant",
            llm_config={"config_list": config_list, "temperature": 0},
            system_message=(
                "You are a helpful assistant. Use the provided tools to complete tasks. "
                "Reply TERMINATE when done."
            ),
        )

        user_proxy = UserProxyAgent(
            name="user",
            human_input_mode="NEVER",
            code_execution_config=False,
            max_consecutive_auto_reply=5,
            is_termination_msg=lambda msg: "TERMINATE" in msg.get("content", ""),
        )

        for td in tools:
            wrapped = self._wrap_tool(td, call_tracker)
            register_function(
                wrapped,
                caller=assistant,
                executor=user_proxy,
                name=td.name,
                description=td.description,
            )

        loop = asyncio.get_event_loop()
        chat_result = await loop.run_in_executor(
            None,
            lambda: user_proxy.initiate_chat(assistant, message=task, max_turns=5),
        )

        final_output = ""
        if hasattr(chat_result, "chat_history") and chat_result.chat_history:
            final_output = chat_result.chat_history[-1].get("content", "")
        elif hasattr(chat_result, "summary"):
            final_output = str(chat_result.summary)

        return AgentExecutionResult(
            tool_calls=call_tracker,
            final_output=final_output,
        )

    @staticmethod
    def _create_config(backend: str) -> list[dict[str, Any]]:
        cfg = get_backend_config(backend)
        provider = cfg["provider"]
        model = cfg["model"]

        if provider == "openai":
            return [{"model": model, "api_key": os.environ.get("OPENAI_API_KEY", "")}]
        if provider == "anthropic":
            return [
                {
                    "model": model,
                    "api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
                    "api_type": "anthropic",
                }
            ]
        if provider == "google":
            return [
                {
                    "model": model,
                    "api_key": os.environ.get("GOOGLE_API_KEY", ""),
                    "api_type": "google",
                }
            ]
        if provider == "ollama":
            return [
                {
                    "model": model,
                    "base_url": "http://localhost:11434/v1",
                    "api_key": "ollama",
                }
            ]
        raise ValueError(f"Unknown provider: {provider}")

    @staticmethod
    def _wrap_tool(td: ToolDef, tracker: list[dict[str, Any]]) -> Any:
        original_func = td.func
        tool_name = td.name

        def tracked(**kwargs: Any) -> str:
            tracker.append({"name": tool_name, "args": kwargs, "output": ""})
            result = original_func(**kwargs)
            tracker[-1]["output"] = str(result)
            return str(result)

        tracked.__name__ = td.name
        tracked.__doc__ = td.description
        tracked.__signature__ = inspect.signature(original_func)
        return tracked
