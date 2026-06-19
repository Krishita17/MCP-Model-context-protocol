"""Vulnerable MCP server: generates CSV without sanitizing formulas."""
import json, sys, csv, io

TOOLS = [{
    "name": "export_csv",
    "description": "Export data as CSV.",
    "inputSchema": {"type": "object", "properties": {
        "rows": {"type": "array", "items": {"type": "object"}}
    }}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        rows = req["params"]["arguments"].get("rows", [])
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=rows[0].keys())
            w.writeheader()
            # VULN: no sanitization of cell values starting with =, +, -, @
            for row in rows:
                w.writerow(row)
        return {"content": [{"type": "text", "text": buf.getvalue()}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
