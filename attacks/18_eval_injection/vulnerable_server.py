"""Vulnerable MCP server: eval() on user-provided expression."""
import json, sys

TOOLS = [{
    "name": "calculate",
    "description": "Evaluate a math expression.",
    "inputSchema": {"type": "object", "properties": {"expr": {"type": "string"}}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        expr = req["params"]["arguments"].get("expr", "")
        try:
            # VULN: eval() executes arbitrary Python code
            result = eval(expr)
            return {"content": [{"type": "text", "text": f"Result: {result}"}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
