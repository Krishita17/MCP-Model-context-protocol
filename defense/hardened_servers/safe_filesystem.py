"""Hardened filesystem — sandboxed with path traversal prevention."""

import json
import os
import sys
import tempfile
from pathlib import Path

SANDBOX = Path(os.environ.get("MCP_FS_ROOT", tempfile.mkdtemp(prefix="mcp_safe_fs_"))).resolve()

TOOLS = [
    {"name": "read_file", "description": "Read a file (sandboxed).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write a file (sandboxed).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "list_dir", "description": "List directory (sandboxed).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "default": "."}}}},
]


def safe_resolve(root: Path, user_path: str) -> Path:
    resolved = (root / user_path).resolve()
    if not str(resolved).startswith(str(root)):
        raise PermissionError(f"Path traversal blocked: {user_path}")
    return resolved


def handle_call(name, args):
    try:
        if name == "read_file":
            p = safe_resolve(SANDBOX, args["path"])
            if not p.exists():
                return {"error": "File not found"}
            return {"content": p.read_text(encoding="utf-8", errors="replace")[:10000]}
        if name == "write_file":
            p = safe_resolve(SANDBOX, args["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            content = args["content"][:50000]
            p.write_text(content, encoding="utf-8")
            return {"message": f"Written {len(content)} bytes"}
        if name == "list_dir":
            p = safe_resolve(SANDBOX, args.get("path", "."))
            if not p.is_dir():
                return {"error": "Not a directory"}
            return {"entries": [{"name": e.name, "type": "dir" if e.is_dir() else "file"} for e in sorted(p.iterdir())]}
    except PermissionError as e:
        return {"error": str(e)}
    return {"error": f"Unknown tool: {name}"}


def handle_jsonrpc(req):
    rid = req.get("id")
    method = req.get("method", "")
    params = req.get("params", {})
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "safe_filesystem", "version": "1.0.0"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        result = handle_call(params.get("name", ""), params.get("arguments", {}))
        return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(result)}], "isError": "error" in result}}
    if method == "notifications/initialized":
        return {}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {method}"}}


if __name__ == "__main__":
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_jsonrpc(req)
        if resp:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
