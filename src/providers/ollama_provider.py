"""Ollama provider — local models via the ollama Python package."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from providers.base import Message, Provider, ToolCall, ToolSpec

try:
    import ollama as _ollama
    _HAS_OLLAMA = True
except ImportError:
    _ollama = None  # type: ignore[assignment]
    _HAS_OLLAMA = False

DEFAULT_MODEL = "qwen2.5"


def _to_ollama_messages(messages: List[Message]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for m in messages:
        msg: Dict[str, Any] = {"role": m.role, "content": m.content}
        if m.role == "assistant" and m.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": tc.arguments},
                }
                for tc in m.tool_calls
            ]
        if m.role == "tool":
            msg["content"] = m.content
        out.append(msg)
    return out


def _to_ollama_tools(tools: List[ToolSpec]) -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.input_schema,
            },
        }
        for t in tools
    ]


def _parse_tool_calls(raw_calls: Any) -> List[ToolCall]:
    calls: List[ToolCall] = []
    if not raw_calls:
        return calls
    for tc in raw_calls:
        fn = tc.get("function", tc)
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"raw": args}
        calls.append(ToolCall(
            id=tc.get("id", uuid.uuid4().hex[:12]),
            name=fn.get("name", ""),
            arguments=args,
        ))
    return calls


class OllamaProvider(Provider):
    """Ollama local model provider."""

    def __init__(self, model: Optional[str] = None, **kwargs: Any) -> None:
        if not _HAS_OLLAMA:
            raise ImportError("The 'ollama' package is required. Install it with: pip install ollama")
        self._model = model or DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, messages: List[Message], tools: Optional[List[ToolSpec]] = None) -> Message:
        kwargs: Dict[str, Any] = {
            "model": self._model,
            "messages": _to_ollama_messages(messages),
        }
        if tools:
            kwargs["tools"] = _to_ollama_tools(tools)

        resp = _ollama.chat(**kwargs)
        msg = resp.get("message", resp)
        content = msg.get("content", "") or ""
        tool_calls = _parse_tool_calls(msg.get("tool_calls"))
        return Message.assistant(content, tool_calls=tool_calls)
