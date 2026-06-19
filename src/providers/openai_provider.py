"""OpenAI provider — GPT models via the openai Python package."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from providers.base import Message, Provider, ToolCall, ToolSpec

try:
    import openai as _openai
    _HAS_OPENAI = True
except ImportError:
    _openai = None  # type: ignore[assignment]
    _HAS_OPENAI = False

DEFAULT_MODEL = "gpt-4o"


def _to_openai_messages(messages: List[Message]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for m in messages:
        if m.role == "system":
            out.append({"role": "system", "content": m.content})
        elif m.role == "user":
            out.append({"role": "user", "content": m.content})
        elif m.role == "assistant":
            msg: Dict[str, Any] = {"role": "assistant", "content": m.content or None}
            if m.tool_calls:
                msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in m.tool_calls
                ]
            out.append(msg)
        elif m.role == "tool":
            out.append({
                "role": "tool",
                "tool_call_id": m.tool_call_id,
                "content": m.content,
            })
    return out


def _to_openai_tools(tools: List[ToolSpec]) -> List[Dict[str, Any]]:
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


def _parse_response(resp: Any) -> Message:
    choice = resp.choices[0].message
    content = choice.content or ""
    tool_calls: List[ToolCall] = []
    if choice.tool_calls:
        for tc in choice.tool_calls:
            args = tc.function.arguments
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"raw": args}
            tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
    return Message.assistant(content, tool_calls=tool_calls)


class OpenAIProvider(Provider):
    """OpenAI chat completion provider."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 base_url: Optional[str] = None, **kwargs: Any) -> None:
        if not _HAS_OPENAI:
            raise ImportError("The 'openai' package is required. Install it with: pip install openai")
        ctor_kwargs: Dict[str, Any] = {}
        if api_key:
            ctor_kwargs["api_key"] = api_key
        if base_url:
            ctor_kwargs["base_url"] = base_url
        self._client = _openai.OpenAI(**ctor_kwargs)
        self._model = model or DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    async def complete(self, messages: List[Message], tools: Optional[List[ToolSpec]] = None) -> Message:
        kwargs: Dict[str, Any] = {
            "model": self._model,
            "messages": _to_openai_messages(messages),
        }
        if tools:
            kwargs["tools"] = _to_openai_tools(tools)
        resp = self._client.chat.completions.create(**kwargs)
        return _parse_response(resp)
