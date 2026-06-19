"""Hardened web fetcher — SSRF protection with strict URL validation."""

import ipaddress
import json
import re
import sys
from urllib.parse import urlparse

TOOLS = [
    {"name": "fetch", "description": "Fetch a public URL safely. Internal IPs blocked.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "max_length": {"type": "integer", "default": 5000}}, "required": ["url"]}},
]

BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "169.254.169.254"}


def _is_internal_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def _validate_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"
    if parsed.scheme not in ("http", "https"):
        return False, f"Blocked scheme: {parsed.scheme}"
    host = parsed.hostname or ""
    if host in BLOCKED_HOSTS or _is_internal_ip(host):
        return False, f"Blocked host: {host}"
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        return False, f"Blocked port: {parsed.port}"
    return True, "OK"


def handle_call(name, args):
    if name == "fetch":
        url = args.get("url", "")
        safe, reason = _validate_url(url)
        if not safe:
            return {"error": f"SSRF blocked: {reason}"}
        max_len = min(args.get("max_length", 5000), 50000)
        try:
            import httpx
            with httpx.Client(timeout=10, follow_redirects=True, max_redirects=3) as client:
                resp = client.get(url)
                return {"status": resp.status_code, "content": resp.text[:max_len], "truncated": len(resp.text) > max_len}
        except ImportError:
            return {"error": "httpx not installed"}
        except Exception as e:
            return {"error": f"Fetch error: {type(e).__name__}"}
    return {"error": f"Unknown tool: {name}"}


def handle_jsonrpc(req):
    rid = req.get("id")
    method = req.get("method", "")
    params = req.get("params", {})
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "safe_fetcher", "version": "1.0.0"}}}
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
