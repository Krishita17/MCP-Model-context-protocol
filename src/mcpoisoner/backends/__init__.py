"""LLM backend configuration and availability checking."""

from __future__ import annotations

import os

import structlog
from dotenv import load_dotenv

load_dotenv()

logger = structlog.get_logger()

BACKEND_MAP: dict[str, dict[str, str | None]] = {
    "gpt-4o": {
        "provider": "openai",
        "model": "gpt-4o",
        "env_key": "OPENAI_API_KEY",
    },
    "gpt-4o-mini": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
    },
    "claude-sonnet": {
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "env_key": "ANTHROPIC_API_KEY",
    },
    "gemini-2.5": {
        "provider": "google",
        "model": "gemini-2.0-flash",
        "env_key": "GOOGLE_API_KEY",
    },
    "llama-3.1-70b": {
        "provider": "ollama",
        "model": "llama3.1:70b",
        "env_key": None,
    },
    "llama-3.1-8b": {
        "provider": "ollama",
        "model": "llama3.1:8b",
        "env_key": None,
    },
}


def available_backends() -> list[str]:
    avail = []
    for name, cfg in BACKEND_MAP.items():
        env_key = cfg["env_key"]
        if env_key is None or os.environ.get(env_key):
            avail.append(name)
        else:
            logger.debug("backend_unavailable", backend=name, missing_key=env_key)
    return avail


def get_backend_config(name: str) -> dict[str, str | None]:
    if name not in BACKEND_MAP:
        raise ValueError(f"Unknown backend: {name}. Available: {list(BACKEND_MAP.keys())}")
    return BACKEND_MAP[name]


def is_backend_available(name: str) -> bool:
    cfg = BACKEND_MAP.get(name)
    if cfg is None:
        return False
    env_key = cfg["env_key"]
    return env_key is None or bool(os.environ.get(env_key))


_verified_ollama: set[str] = set()


def verify_ollama_connection(model: str = "llama3.1:8b") -> None:
    """Hard fail if Ollama is not reachable — never silently fall back.

    Honors the OLLAMA_HOST env var so a deliberately broken host (used to test
    that failures crash loudly) surfaces a fatal error instead of fake results.
    Cached per (host, model) so a matrix run only pays the probe once.
    """
    import httpx

    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    key = f"{host}|{model}"
    if key in _verified_ollama:
        return
    try:
        response = httpx.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": "respond with the single word READY", "stream": False},
            # Generous timeout: the first call cold-loads the model (~5GB) into
            # RAM, which can take 30-40s. A short timeout would false-fail here.
            timeout=120.0,
        )
        response.raise_for_status()
        reply = response.json().get("response", "").strip()
        print(f"[OLLAMA VERIFIED] Host: {host} | Model: {model} | Response: {reply!r}")
        if not reply:
            raise RuntimeError("Ollama returned an empty response")
    except Exception as e:
        raise RuntimeError(
            f"\n[FATAL] Ollama not reachable at {host}\n"
            f"Error: {e}\n"
            f"Fix: run 'ollama serve' and 'ollama pull {model}', then retry.\n"
        ) from e
    _verified_ollama.add(key)
