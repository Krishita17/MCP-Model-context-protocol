"""Agent loop — drives a Provider + MCPHost through iterative tool use."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from providers.base import Message, Provider, ToolSpec
from host.client import MCPHost

logger = logging.getLogger(__name__)

EventCallback = Callable[[str, Dict[str, Any]], None]


class Agent:
    """Agentic loop: model generates tool calls, host executes them, repeat.

    Args:
        provider: The LLM provider to use.
        host: Connected MCPHost with tools.
        system_prompt: Initial system instruction.
        max_steps: Safety limit on tool-call rounds.
        on_event: Optional callback ``(event_name, payload)`` for logging.
    """

    def __init__(
        self,
        provider: Provider,
        host: MCPHost,
        system_prompt: str = "You are a helpful assistant with access to tools.",
        max_steps: int = 20,
        on_event: Optional[EventCallback] = None,
    ) -> None:
        self.provider = provider
        self.host = host
        self.system_prompt = system_prompt
        self.max_steps = max_steps
        self._on_event = on_event

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        if self._on_event:
            try:
                self._on_event(event, payload)
            except Exception:
                logger.exception("Event callback error for %s", event)

    async def run(self, user_text: str) -> str:
        """Run the agent loop to completion and return the final assistant text.

        Args:
            user_text: The user's query.

        Returns:
            The assistant's final textual response.
        """
        messages: List[Message] = [
            Message.system(self.system_prompt),
            Message.user(user_text),
        ]
        tools = self.host.tools

        self._emit("agent_start", {"user_text": user_text, "tools": len(tools)})

        for step in range(self.max_steps):
            self._emit("step_start", {"step": step})

            response = await self.provider.complete(messages, tools=tools if tools else None)
            messages.append(response)

            if not response.tool_calls:
                self._emit("agent_done", {"step": step, "content": response.content})
                return response.content

            # Execute each tool call
            for tc in response.tool_calls:
                self._emit("tool_call", {
                    "step": step,
                    "tool": tc.name,
                    "arguments": tc.arguments,
                    "id": tc.id,
                })
                try:
                    result_text = await self.host.call_tool(tc.name, tc.arguments)
                except Exception as exc:
                    result_text = f"Error calling {tc.name}: {exc}"
                    logger.exception("Tool call failed: %s", tc.name)

                self._emit("tool_result", {
                    "step": step,
                    "tool": tc.name,
                    "id": tc.id,
                    "result": result_text[:500],
                })
                messages.append(Message.tool_result(tc.id, tc.name, result_text))

        # Exceeded max steps — ask model for a final answer without tools
        self._emit("max_steps_reached", {"max_steps": self.max_steps})
        messages.append(Message.user(
            "You have reached the maximum number of tool-call rounds. "
            "Please provide your best answer now without using any more tools."
        ))
        response = await self.provider.complete(messages, tools=None)
        self._emit("agent_done", {"step": self.max_steps, "content": response.content})
        return response.content
