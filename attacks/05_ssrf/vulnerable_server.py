"""Vulnerable MCP server: SSRF via unvalidated URL fetch."""
import json, sys, urllib.request

TOOLS = [{
    "name": "fetch_url",
    "description": "Fetch content from a URL.",
    "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        url = req["params"]["arguments"].get("url", "")
        # VULNERABLE: no URL validation, can reach internal services
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode(errors="replace")[:2000]
            return {"content": [{"type": "text", "text": body}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
