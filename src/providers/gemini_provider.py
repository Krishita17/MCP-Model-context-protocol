"""Google Gemini provider — uses the google-generativeai package."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from providers.base import Message, Provider, ToolCall, ToolSpec

try:
    import google.generativeai as _genai
    _HAS_GENAI = True
except ImportError:
    _genai = None  # type: ignore[assignment]
    _HAS_GENAI = False

DEFAULT_MODEL = "gemini-1.5-pro"


def _to_gemini_tools(tools: List[ToolSpec]) -> Any:
    """Build a Gemini Tool containing function declarations."""
    declarations = []
    for t in tools:
        schema = dict(t.input_schema)
        schema.pop("additionalProperties", None)
        declarations.append({
            "name": t.name,
            "description": t.description,
            "parameters": schema,
        })
    return [{"function_declarations": declarations}]


def _to_gemini_history(messages: List[Message]):
    """Convert neutral messages to Gemini contents list.

    Returns (system_instruction, contents).
    """
    system_instruction: Optional[str] = None
    contents: List[Dict[str, Any]] = []

    for m in messages:
        if m.role == "system":
            system_instruction = m.content
        elif m.role == "user":
            contents.append({"role": "user", "parts": [{"text": m.content}]})
        elif m.role == "assistant":
            parts: List[Dict[str, Any]] = []
            if m.content:
                parts.append({"text": m.content})
            for tc in m.tool_calls:
                parts.append({
                    "function_call": {
                        "name": tc.name,
                        "args": tc.arguments,
                    }
                })
            contents.append({"role": "model", "parts": parts})
        elif m.role == "tool":
            contents.append({
                "role": "user",
                "parts": [
                    {
                        "function_response": {
                            "name": m.name or "",
                            "response": {"result": m.content},
                        }
                    }
                ],
            })
    return system_instruction, contents


def _parse_response(resp: Any) -> Message:
    content = ""
    tool_calls: List[ToolCall] = []
    for candidate in resp.candidates:
        for part in candidate.content.parts:
            if hasattr(part, "text") and part.text:
                content += part.text
            if hasattr(part, "function_call") and part.function_call:
                fc = part.function_call
                args = dict(fc.args) if fc.args else {}
                tool_calls.append(ToolCall(
                    id=uuid.uuid4().hex[:12],
                    name=fc.name,
                    arguments=args,
                ))
    return Message.assistant(content, tool_calls=tool_calls)


class GeminiProvider(Provider):
    """Google Gemini provider."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, **kwargs: Any) -> None:
        if not _HAS_GENAI:
            raise ImportError(
                "The 'google-generativeai' package is required. "
                "Install it with: pip install google-generativeai"
            )
        if api_key:
            _genai.configure(api_key=api_key)
        self._model_name = model or DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def model(self) -> str:
        return self._model_name

    async def complete(self, messages: List[Message], tools: Optional[List[ToolSpec]] = None) -> Message:
        system_instruction, contents = _to_gemini_history(messages)

        gen_kwargs: Dict[str, Any] = {}
        if system_instruction:
            gen_kwargs["system_instruction"] = system_instruction

        gmodel = _genai.GenerativeModel(self._model_name, **gen_kwargs)

        gen_config: Dict[str, Any] = {}
        call_kwargs: Dict[str, Any] = {"contents": contents}
        if tools:
            call_kwargs["tools"] = _to_gemini_tools(tools)

        resp = gmodel.generate_content(**call_kwargs)
        return _parse_response(resp)
