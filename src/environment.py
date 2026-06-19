"""Environment readiness checks for the MCP Security Suite."""

from __future__ import annotations

import importlib
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Check:
    """Result of a single environment check."""
    name: str
    ok: bool
    detail: str
    hint: str = ""


def gather() -> list[Check]:
    """Run all environment checks and return a list of Check results."""
    checks: list[Check] = []

    # 1. Python version
    ver = platform.python_version()
    major, minor = sys.version_info[:2]
    ok = major == 3 and minor >= 10
    checks.append(Check(
        name="Python version",
        ok=ok,
        detail=f"{ver} ({'3.10+ required' if not ok else 'OK'})",
        hint="Install Python 3.10 or later from python.org" if not ok else "",
    ))

    # 2. LLM providers
    provider_names = ["ollama", "openai", "anthropic", "gemini", "openrouter"]
    env_keys = {
        "ollama": None,  # no key needed, check connectivity
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "gemini": "GOOGLE_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }
    for pname in provider_names:
        env_var = env_keys.get(pname)
        if env_var is None:
            # Ollama — check if binary exists
            has_binary = shutil.which("ollama") is not None
            checks.append(Check(
                name=f"Provider: {pname}",
                ok=has_binary,
                detail="ollama binary found" if has_binary else "ollama binary not in PATH",
                hint="Install Ollama from https://ollama.com" if not has_binary else "",
            ))
        else:
            has_key = bool(os.environ.get(env_var))
            checks.append(Check(
                name=f"Provider: {pname}",
                ok=has_key,
                detail=f"{env_var} {'set' if has_key else 'not set'}",
                hint=f"Set {env_var} environment variable" if not has_key else "",
            ))

    # 3. Ollama reachable
    ollama_ok = False
    ollama_detail = "not checked"
    try:
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                ollama_ok = True
                ollama_detail = "Ollama API responding on :11434"
    except Exception as e:
        ollama_detail = f"Ollama not reachable: {type(e).__name__}"
    checks.append(Check(
        name="Ollama reachable",
        ok=ollama_ok,
        detail=ollama_detail,
        hint="Start Ollama with: ollama serve" if not ollama_ok else "",
    ))

    # 4. GUI installed (PySide6)
    gui_ok = False
    try:
        importlib.import_module("PySide6")
        gui_ok = True
        gui_detail = "PySide6 available"
    except ImportError:
        gui_detail = "PySide6 not installed"
    checks.append(Check(
        name="GUI (PySide6)",
        ok=gui_ok,
        detail=gui_detail,
        hint="pip install PySide6" if not gui_ok else "",
    ))

    # 5. Lab contents — check key source directories
    src_root = Path(__file__).resolve().parent
    expected_dirs = [
        "mcpoisoner/attacks",
        "mcpshield",
        "cryptomcp",
        "guardrails",
        "defenselab",
        "governance",
        "providers",
    ]
    present = []
    missing = []
    for d in expected_dirs:
        if (src_root / d).is_dir():
            present.append(d)
        else:
            missing.append(d)

    checks.append(Check(
        name="Lab contents",
        ok=len(missing) == 0,
        detail=f"{len(present)}/{len(expected_dirs)} directories present"
              + (f" (missing: {', '.join(missing)})" if missing else ""),
        hint="Re-clone the repository to get all components" if missing else "",
    ))

    # 6. Key Python packages
    for pkg_name, pip_name in [
        ("typer", "typer"),
        ("rich", "rich"),
        ("structlog", "structlog"),
    ]:
        try:
            importlib.import_module(pkg_name)
            checks.append(Check(name=f"Package: {pkg_name}", ok=True, detail="installed"))
        except ImportError:
            checks.append(Check(
                name=f"Package: {pkg_name}",
                ok=False,
                detail="not installed",
                hint=f"pip install {pip_name}",
            ))

    return checks


def stats() -> dict:
    """Count attack modules and guardrails in the project."""
    src_root = Path(__file__).resolve().parent
    result: dict = {"attack_modules": 0, "guardrails": 0}

    # Count attack modules
    attacks_dir = src_root / "mcpoisoner" / "attacks"
    if attacks_dir.is_dir():
        result["attack_modules"] = sum(
            1 for f in attacks_dir.glob("*.py")
            if f.name not in ("__init__.py", "base.py")
        )

    # Count guardrail modules
    gr_dir = src_root / "guardrails"
    if gr_dir.is_dir():
        result["guardrails"] = sum(
            1 for f in gr_dir.glob("*.py")
            if f.name != "__init__.py"
        )

    return result


def all_ok() -> bool:
    """Return True if all environment checks pass."""
    return all(c.ok for c in gather())
