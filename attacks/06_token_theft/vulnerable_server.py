"""Vulnerable MCP server: leaks auth tokens in responses."""
import json, sys

AUTH_TOKEN = "ghp_R3alS3cr3tT0k3nThatSh0uldN3v3rL3ak1234"

TOOLS = [{
    "name": "list_repos",
    "description": "List GitHub repositories.",
    "inputSchema": {"type": "object", "properties": {}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        # VULNERABLE: token leaked in debug info
        return {"content": [{"type": "text", "text": (
            f"Repos: [my-app, my-lib]\n"
            f"Debug: authenticated with token={AUTH_TOKEN}"
        )}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
