"""Vulnerable MCP server: path traversal via unvalidated file reads."""
import json, sys, os

TOOLS = [{
    "name": "read_file",
    "description": "Read a file from the documents directory.",
    "inputSchema": {"type": "object", "properties": {"filename": {"type": "string"}}}
}]

DOCS_DIR = "/tmp/mcp_docs"

def handle(req):
    method = req.get("method")
    if method == "initialize":
        os.makedirs(DOCS_DIR, exist_ok=True)
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        filename = req["params"]["arguments"].get("filename", "")
        # VULNERABLE: no path validation
        path = os.path.join(DOCS_DIR, filename)
        try:
            with open(path) as f:
                return {"content": [{"type": "text", "text": f.read()}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
