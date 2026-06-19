"""Provider abstraction — neutral dataclasses and ABC."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolSpec:
    """Neutral tool specification passed to any provider."""
    name: str
    description: str
    input_schema: Dict[str, Any]


@dataclass
class ToolCall:
    """A single tool invocation returned by the model."""
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class Message:
    """Provider-neutral chat message."""
    role: str  # "system", "user", "assistant", "tool"
    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    tool_call_id: Optional[str] = None  # set when role == "tool"
    name: Optional[str] = None  # tool name for tool results

    # Convenience helpers ------------------------------------------------

    @staticmethod
    def system(text: str) -> "Message":
        return Message(role="system", content=text)

    @staticmethod
    def user(text: str) -> "Message":
        return Message(role="user", content=text)

    @staticmethod
    def assistant(text: str, tool_calls: Optional[List[ToolCall]] = None) -> "Message":
        return Message(role="assistant", content=text, tool_calls=tool_calls or [])

    @staticmethod
    def tool_result(tool_call_id: str, name: str, content: str) -> "Message":
        return Message(role="tool", content=content, tool_call_id=tool_call_id, name=name)


class Provider(ABC):
    """Abstract base for LLM providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short provider identifier (e.g. 'openai')."""

    @property
    @abstractmethod
    def model(self) -> str:
        """Model id currently in use."""

    @abstractmethod
    async def complete(self, messages: List[Message], tools: Optional[List[ToolSpec]] = None) -> Message:
        """Send messages (and optional tool definitions) to the model and return an assistant Message."""
