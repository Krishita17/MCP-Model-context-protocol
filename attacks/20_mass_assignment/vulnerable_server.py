"""Vulnerable MCP server: unvalidated bulk property update."""
import json, sys

USERS = {
    "bob": {"name": "bob", "email": "bob@co.com", "role": "user", "active": True}
}

TOOLS = [{
    "name": "update_profile",
    "description": "Update user profile fields.",
    "inputSchema": {"type": "object", "properties": {
        "user": {"type": "string"}, "updates": {"type": "object"}
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
        user = args.get("user", "")
        updates = args.get("updates", {})
        if user in USERS:
            # VULN: blindly merges all fields -- attacker can set role, active, etc.
            USERS[user].update(updates)
            return {"content": [{"type": "text",
                    "text": f"Updated {user}: {json.dumps(USERS[user])}"}]}
        return {"content": [{"type": "text", "text": "User not found"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
