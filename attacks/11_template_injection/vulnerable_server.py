"""Vulnerable MCP server: Python format string injection."""
import json, sys, os

TOOLS = [{
    "name": "greet",
    "description": "Generate a greeting message.",
    "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}
}]

# Simulated config object with secrets
class Config:
    db_password = "supersecret123"
    api_key = "sk-live-abc"

config = Config()

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = req["params"]["arguments"].get("name", "")
        # VULN: .format() on user input can leak object attributes
        template = f"Hello, {name}! Welcome."
        try:
            msg = template.format(config=config)
        except Exception:
            msg = template
        return {"content": [{"type": "text", "text": msg}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
