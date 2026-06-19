"""LLM provider abstraction layer."""

from providers.base import Provider, ToolSpec, ToolCall, Message


def build_provider(name: str, **kwargs) -> Provider:
    """Build a provider by name.

    Args:
        name: One of 'ollama', 'openai', 'anthropic', 'gemini', 'openrouter'.
        **kwargs: Passed to the provider constructor (model, api_key, base_url, etc.)

    Returns:
        A Provider instance.
    """
    name = name.lower().strip()
    if name == "ollama":
        from providers.ollama_provider import OllamaProvider
        return OllamaProvider(**kwargs)
    elif name == "openai":
        from providers.openai_provider import OpenAIProvider
        return OpenAIProvider(**kwargs)
    elif name == "anthropic":
        from providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider(**kwargs)
    elif name == "gemini":
        from providers.gemini_provider import GeminiProvider
        return GeminiProvider(**kwargs)
    elif name == "openrouter":
        from providers.openrouter_provider import OpenRouterProvider
        return OpenRouterProvider(**kwargs)
    else:
        raise ValueError(f"Unknown provider: {name!r}. Choose from: ollama, openai, anthropic, gemini, openrouter")


__all__ = ["build_provider", "Provider", "ToolSpec", "ToolCall", "Message"]
