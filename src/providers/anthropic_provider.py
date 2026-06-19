"""Anthropic provider — Claude models via the anthropic Python package."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from providers.base import Message, Provider, ToolCall, ToolSpec

try:
    import anthropic as _anthropic
    _HAS_ANTHROPIC = True
except ImportError:
    _anthropic = None  # type: ignore[assignment]
    _HAS_ANTHROPIC = False

DEFAULT_MODEL = "claude-sonnet-4-20250514"


def _to_anthropic_messages(messages: List[Message]):
    """Convert neutral messages to Anthropic format.

    Returns (system_prompt, message_list).
    """
    system_prompt = ""
    out: List[Dict[str, Any]] = []

    for m in messages:
        if m.role == "system":
            system_prompt = m.content
        elif m.role == "user":
            out.append({"role": "user", "content": m.content})
        elif m.role == "assistant":
            content_blocks: List[Dict[str, Any]] = []
            if m.content:
                content_blocks.append({"type": "text", "text": m.content})
            for tc in m.tool_calls:
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.name,
                    "input": tc.arguments,
                })
            out.append({"role": "assistant", "content": content_blocks})
        elif m.role == "tool":
            out.append({
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id,
                        "content": m.content,
                    }
                ],
            })

    return system_prompt, out


def _to_anthropic_tools(tools: List[ToolSpec]) -> List[Dict[str, Any]]:
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
        }
        for t in tools
    ]


def _parse_response(resp: Any) -> Message:
    content = ""
    tool_calls: List[ToolCall] = []
    for block in resp.content:
        if block.type == "text":
            content += block.text
        elif block.type == "tool_use":
            tool_calls.append(ToolCall(
                id=block.id,
                name=block.name,
                arguments=block.input if isinstance(block.input, dict) else {},
            ))
    return Message.assistant(content, tool_calls=tool_calls)


class AnthropicProvider(Provider):
    """Anthropic Claude provider."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, **kwargs: Any) -> None:
        if not _HAS_ANTHROPIC:
            raise ImportError("The 'anthropic' package is required. Install it with: pip install anthropic")
        ctor_kwargs: Dict[str, Any] = {}
        if api_key:
            ctor_kwargs["api_key"] = api_key
        self._client = _anthropic.Anthropic(**ctor_kwargs)
        self._model = model or DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, messages: List[Message], tools: Optional[List[ToolSpec]] = None) -> Message:
        system_prompt, anthropic_messages = _to_anthropic_messages(messages)
        kwargs: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": anthropic_messages,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            kwargs["tools"] = _to_anthropic_tools(tools)
        resp = self._client.messages.create(**kwargs)
        return _parse_response(resp)
