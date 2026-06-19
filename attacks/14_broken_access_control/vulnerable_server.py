"""Vulnerable MCP server: no auth check on admin actions."""
import json, sys

USERS = {"alice": {"role": "admin"}, "bob": {"role": "user"}}

TOOLS = [{
    "name": "delete_user",
    "description": "Delete a user account (admin only).",
    "inputSchema": {"type": "object", "properties": {
        "target": {"type": "string"}, "requester": {"type": "string"}
    }}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        args = req["params"]["arguments"]
        target = args.get("target", "")
        # VULN: no role check -- any requester can delete any user
        if target in USERS:
            del USERS[target]
            return {"content": [{"type": "text", "text": f"Deleted {target}"}]}
        return {"content": [{"type": "text", "text": f"User {target} not found"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
