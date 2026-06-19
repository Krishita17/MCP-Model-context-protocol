"""Vulnerable MCP server: writes to arbitrary paths without sandboxing."""
import json, sys, os

TOOLS = [{
    "name": "save_note",
    "description": "Save a note to a file.",
    "inputSchema": {"type": "object", "properties": {
        "path": {"type": "string"}, "content": {"type": "string"}
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
        path = args.get("path", "note.txt")
        content = args.get("content", "")
        # VULN: no path validation, no sandbox -- can write to ~/.bashrc, crontab, etc.
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
            return {"content": [{"type": "text", "text": f"Saved to {path}"}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
