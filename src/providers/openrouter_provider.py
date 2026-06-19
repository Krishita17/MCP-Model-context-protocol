"""OpenRouter provider — uses the OpenAI SDK with a custom base_url."""

from __future__ import annotations

from typing import Any, Optional

from providers.openai_provider import OpenAIProvider

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "openai/gpt-4o"


class OpenRouterProvider(OpenAIProvider):
    """OpenRouter-backed provider (OpenAI-compatible API)."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 base_url: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(
            model=model or DEFAULT_MODEL,
            api_key=api_key,
            base_url=base_url or OPENROUTER_BASE_URL,
            **kwargs,
        )

    @property
    def name(self) -> str:
        return "openrouter"
