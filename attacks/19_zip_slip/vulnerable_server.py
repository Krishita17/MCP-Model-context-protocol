"""Vulnerable MCP server: extracts zip without checking entry paths."""
import json, sys, zipfile, io, base64, os

TOOLS = [{
    "name": "extract_zip",
    "description": "Extract a base64-encoded zip archive.",
    "inputSchema": {"type": "object", "properties": {
        "data": {"type": "string"}, "dest": {"type": "string"}
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
        data = base64.b64decode(args.get("data", ""))
        dest = args.get("dest", "/tmp/extract")
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            # VULN: no check for "../" in entry names (zip slip)
            for entry in zf.namelist():
                target = os.path.join(dest, entry)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as f:
                    f.write(zf.read(entry))
            return {"content": [{"type": "text",
                    "text": f"Extracted {len(zf.namelist())} files to {dest}"}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}
    return {"error": {"code": -32601, "message": "Method not found"}}

for line in sys.stdin:
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": handle(req)}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
