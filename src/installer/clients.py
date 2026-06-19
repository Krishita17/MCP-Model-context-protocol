"""Claude Desktop MCP server installer."""

from __future__ import annotations

import json
import os
import pathlib
import platform
import sys
from typing import Any, Dict


def _claude_desktop_config_path() -> pathlib.Path:
    """Locate the Claude Desktop configuration file."""
    system = platform.system()
    if system == "Darwin":
        return pathlib.Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        return pathlib.Path(appdata) / "Claude" / "claude_desktop_config.json"
    else:
        # Linux / fallback
        return pathlib.Path.home() / ".config" / "claude" / "claude_desktop_config.json"


def render_mcp_json(spec: Any) -> Dict[str, Any]:
    """Render a ServerSpec into the JSON snippet expected by Claude Desktop.

    Args:
        spec: A ServerSpec-like object with name, command, args, env attributes.

    Returns:
        A dict suitable for insertion into claude_desktop_config.json under
        ``mcpServers``.
    """
    entry: Dict[str, Any] = {
        "command": spec.command,
        "args": list(spec.args) if spec.args else [],
    }
    if spec.env:
        entry["env"] = dict(spec.env)
    return {spec.name: entry}


def install_to_claude_desktop(spec: Any) -> pathlib.Path:
    """Write a server config entry into Claude Desktop's configuration file.

    Creates the config file and parent directories if they don't exist.

    Args:
        spec: A ServerSpec-like object.

    Returns:
        Path to the config file that was written.
    """
    config_path = _claude_desktop_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing config or start fresh
    if config_path.exists():
        with open(config_path, "r") as f:
            try:
                config = json.load(f)
            except json.JSONDecodeError:
                config = {}
    else:
        config = {}

    if "mcpServers" not in config:
        config["mcpServers"] = {}

    # Merge in the new server entry
    snippet = render_mcp_json(spec)
    config["mcpServers"].update(snippet)

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    return config_path
