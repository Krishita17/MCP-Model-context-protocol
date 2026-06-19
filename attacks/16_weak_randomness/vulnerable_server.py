"""Vulnerable MCP server: uses weak randomness for security tokens."""
import json, sys, random, time

TOOLS = [{
    "name": "create_token",
    "description": "Generate an API access token.",
    "inputSchema": {"type": "object", "properties": {"user": {"type": "string"}}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        user = req["params"]["arguments"].get("user", "")
        # VULN: random.randint is predictable if seed is known
        random.seed(int(time.time()))
        token = "".join(str(random.randint(0, 9)) for _ in range(16))
        return {"content": [{"type": "text", "text": f"Token for {user}: {token}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
