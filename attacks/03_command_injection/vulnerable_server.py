"""Vulnerable MCP server: shell=True command injection."""
import json, subprocess, sys

TOOLS = [{
    "name": "grep_logs",
    "description": "Search log files for a pattern.",
    "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string"}}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        pattern = req["params"]["arguments"].get("pattern", "")
        # VULNERABLE: shell=True with unsanitized input
        result = subprocess.run(
            f"grep -r '{pattern}' /var/log/ 2>/dev/null || echo 'no matches'",
            shell=True, capture_output=True, text=True,
        )
        return {"content": [{"type": "text", "text": result.stdout}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
