"""Central configuration — provider configs, server registry, sandbox."""

from __future__ import annotations

import os
import pathlib
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — rely on real env vars

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SERVERS_DIR = _PROJECT_ROOT / "servers"
_SANDBOX_DIR = _PROJECT_ROOT / "sandbox"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ProviderConfig(BaseModel):
    """Configuration for a single LLM provider."""
    name: str
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None

    @property
    def ready(self) -> bool:
        """True when enough info is present to instantiate the provider."""
        if self.name == "ollama":
            return True  # local, no key needed
        if self.name in ("openai", "anthropic", "gemini", "openrouter"):
            return bool(self.api_key)
        return False


class ServerSpec(BaseModel):
    """Specification for an MCP server to connect to."""
    name: str
    description: str = ""
    transport: str = "stdio"
    command: str = "python"
    args: List[str] = Field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    url: Optional[str] = None  # for SSE / streamable-HTTP transports


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_providers() -> Dict[str, ProviderConfig]:
    """Read provider configurations from environment variables.

    Recognised env vars:
        OLLAMA_MODEL, ANTHROPIC_API_KEY, OPENAI_API_KEY,
        GEMINI_API_KEY, OPENROUTER_API_KEY
    """
    providers: Dict[str, ProviderConfig] = {}

    providers["ollama"] = ProviderConfig(
        name="ollama",
        model=os.getenv("OLLAMA_MODEL", "qwen2.5"),
    )
    providers["anthropic"] = ProviderConfig(
        name="anthropic",
        model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
        api_key=os.getenv("ANTHROPIC_API_KEY"),
    )
    providers["openai"] = ProviderConfig(
        name="openai",
        model=os.getenv("OPENAI_MODEL", "gpt-4o"),
        api_key=os.getenv("OPENAI_API_KEY"),
    )
    providers["gemini"] = ProviderConfig(
        name="gemini",
        model=os.getenv("GEMINI_MODEL", "gemini-1.5-pro"),
        api_key=os.getenv("GEMINI_API_KEY"),
    )
    providers["openrouter"] = ProviderConfig(
        name="openrouter",
        model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o"),
        api_key=os.getenv("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
    )

    return providers


def load_registry() -> Dict[str, ServerSpec]:
    """Return the registry of bundled MCP servers found in the servers/ directory."""
    registry: Dict[str, ServerSpec] = {}

    server_defs = {
        "calculator": "Simple arithmetic calculator server",
        "notes": "Note-taking server with persistent storage",
        "filesystem": "Sandboxed file-system access server",
        "web_fetch": "Web page fetching / URL retrieval server",
    }

    for name, description in server_defs.items():
        server_dir = _SERVERS_DIR / name
        main_file = server_dir / "main.py"
        if not main_file.exists():
            # Try server.py as fallback
            main_file = server_dir / "server.py"
        if main_file.exists():
            registry[name] = ServerSpec(
                name=name,
                description=description,
                transport="stdio",
                command="python",
                args=[str(main_file)],
            )

    return registry


def ensure_sandbox() -> pathlib.Path:
    """Create and return the sandbox directory."""
    _SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    return _SANDBOX_DIR
