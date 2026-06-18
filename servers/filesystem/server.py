"""Filesystem MCP Server — sandboxed file operations for attack/defense demos.

Deliberately constrained to a sandbox directory to prevent path-traversal.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


SANDBOX = Path(tempfile.mkdtemp(prefix="mcp_fs_sandbox_")).resolve()

TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file in the sandbox directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path within the sandbox"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file in the sandbox directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path within the sandbox"},
                "content": {"type": "string", "description": "File content to write"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_directory",
        "description": "List files and directories in the sandbox.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative directory path", "default": "."},
            },
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file from the sandbox directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path within the sandbox"},
            },
            "required": ["path"],
        },
    },
]


def _safe_path(rel: str) -> Path | None:
    """Resolve a path and ensure it stays within the sandbox."""
    target = (SANDBOX / rel).resolve()
    if not str(target).startswith(str(SANDBOX)):
        return None
    return target


def handle_call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    match tool_name:
        case "read_file":
            path = _safe_path(arguments["path"])
            if path is None:
                return {"error": "Path traversal blocked"}
            if not path.exists():
                return {"error": f"File not found: {arguments['path']}"}
            return {"content": path.read_text(encoding="utf-8", errors="replace")}
        case "write_file":
            path = _safe_path(arguments["path"])
            if path is None:
                return {"error": "Path traversal blocked"}
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(arguments["content"], encoding="utf-8")
            return {"message": f"Written {len(arguments['content'])} bytes to {arguments['path']}"}
        case "list_directory":
            rel = arguments.get("path", ".")
            path = _safe_path(rel)
            if path is None:
                return {"error": "Path traversal blocked"}
            if not path.is_dir():
                return {"error": f"Not a directory: {rel}"}
            entries = []
            for entry in sorted(path.iterdir()):
                entries.append({
                    "name": entry.name,
                    "type": "directory" if entry.is_dir() else "file",
                    "size": entry.stat().st_size if entry.is_file() else 0,
                })
            return {"entries": entries, "sandbox": str(SANDBOX)}
        case "delete_file":
            path = _safe_path(arguments["path"])
            if path is None:
                return {"error": "Path traversal blocked"}
            if not path.exists():
                return {"error": f"File not found: {arguments['path']}"}
            path.unlink()
            return {"message": f"Deleted {arguments['path']}"}
        case _:
            return {"error": f"Unknown tool: {tool_name}"}


def handle_jsonrpc(request: dict) -> dict:
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "filesystem", "version": "1.0.0"},
        }}
    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    elif method == "tools/call":
        result = handle_call(params.get("name", ""), params.get("arguments", {}))
        is_error = "error" in result
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": json.dumps(result)}],
            "isError": is_error,
        }}
    elif method == "notifications/initialized":
        return {}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown: {method}"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle_jsonrpc(request)
        if response:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
