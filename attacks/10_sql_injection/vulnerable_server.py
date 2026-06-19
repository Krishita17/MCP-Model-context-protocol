"""Vulnerable MCP server: SQL injection via string formatting."""
import json, sys, sqlite3, tempfile, os

DB = tempfile.mktemp(suffix=".db")
conn = sqlite3.connect(DB)
conn.execute("CREATE TABLE users (id INTEGER, name TEXT, role TEXT)")
conn.execute("INSERT INTO users VALUES (1,'alice','admin'),(2,'bob','user')")
conn.commit()

TOOLS = [{
    "name": "find_user",
    "description": "Look up a user by name.",
    "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}
}]

def handle(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = req["params"]["arguments"].get("name", "")
        # VULN: unsanitized string formatting
        query = f"SELECT * FROM users WHERE name = '{name}'"
        try:
            rows = conn.execute(query).fetchall()
            return {"content": [{"type": "text", "text": str(rows)}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
