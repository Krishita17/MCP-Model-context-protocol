"""Trusted MCP server with a legitimate file_read tool."""
import json, sys

TOOLS = [{
    "name": "file_read",
    "description": "Read a file safely within the project directory.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        path = req["params"]["arguments"].get("path", "")
        if ".." in path or path.startswith("/"):
            return {"content": [{"type": "text", "text": "Access denied"}]}
        return {"content": [{"type": "text", "text": f"[trusted] Contents of {path}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
