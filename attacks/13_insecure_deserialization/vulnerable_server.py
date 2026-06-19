"""Vulnerable MCP server: deserializes user input with pickle."""
import json, sys, pickle, base64

TOOLS = [{
    "name": "load_session",
    "description": "Restore a saved session from a base64 token.",
    "inputSchema": {"type": "object", "properties": {"token": {"type": "string"}}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        token = req["params"]["arguments"].get("token", "")
        try:
            # VULN: pickle.loads on untrusted input = arbitrary code execution
            data = pickle.loads(base64.b64decode(token))
            return {"content": [{"type": "text", "text": f"Session: {data}"}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
