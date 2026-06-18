"""Web Fetch MCP Server — HTTP fetching with safety controls for demos.

Demonstrates SSRF prevention with URL allowlist validation.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any
from urllib.parse import urlparse


TOOLS = [
    {
        "name": "fetch_url",
        "description": "Fetch the content of a public URL. Only HTTP/HTTPS allowed. Internal IPs are blocked.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch"},
                "max_length": {"type": "integer", "description": "Max response length in chars", "default": 5000},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_url_safety",
        "description": "Check if a URL is safe to fetch (not internal, valid scheme, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to check"},
            },
            "required": ["url"],
        },
    },
]

BLOCKED_HOSTS = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"0\.0\.0\.0|169\.254\.\d+\.\d+|\[::1\]|metadata\.google\.internal)$",
    re.IGNORECASE,
)


def _is_safe_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"
    if parsed.scheme not in ("http", "https"):
        return False, f"Blocked scheme: {parsed.scheme}"
    host = parsed.hostname or ""
    if BLOCKED_HOSTS.match(host):
        return False, f"Blocked internal host: {host}"
    return True, "URL is safe"


def handle_call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    match tool_name:
        case "fetch_url":
            url = arguments["url"]
            safe, reason = _is_safe_url(url)
            if not safe:
                return {"error": f"SSRF protection: {reason}"}
            max_len = arguments.get("max_length", 5000)
            try:
                import httpx
                with httpx.Client(timeout=10, follow_redirects=True) as client:
                    resp = client.get(url)
                    text = resp.text[:max_len]
                    return {
                        "status_code": resp.status_code,
                        "content": text,
                        "truncated": len(resp.text) > max_len,
                        "content_type": resp.headers.get("content-type", ""),
                    }
            except ImportError:
                return {"error": "httpx not installed — install with: pip install httpx"}
            except Exception as exc:
                return {"error": f"Fetch failed: {exc}"}
        case "check_url_safety":
            safe, reason = _is_safe_url(arguments["url"])
            return {"safe": safe, "reason": reason}
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
            "serverInfo": {"name": "web_fetch", "version": "1.0.0"},
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
