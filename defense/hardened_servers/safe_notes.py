"""Hardened notes server — parameterized queries, input validation, scrubbed output."""

import json
import re
import sys
import uuid
from datetime import datetime, timezone

_notes: dict[str, dict] = {}
MAX_TITLE = 200
MAX_BODY = 10000

TOOLS = [
    {"name": "create_note", "description": "Create a note with title and body.",
     "inputSchema": {"type": "object", "properties": {"title": {"type": "string", "maxLength": MAX_TITLE}, "body": {"type": "string", "maxLength": MAX_BODY}}, "required": ["title", "body"]}},
    {"name": "read_note", "description": "Read a note by ID.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
    {"name": "list_notes", "description": "List all notes.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "search_notes", "description": "Search notes by keyword.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "maxLength": 100}}, "required": ["query"]}},
]

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|password|token|bearer)\s*[:=]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}\b"),
]


def _scrub(text: str) -> str:
    for pat in SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def _validate_id(note_id: str) -> bool:
    return bool(re.match(r"^[a-f0-9]{8}$", note_id))


def handle_call(name, args):
    if name == "create_note":
        title = args.get("title", "")[:MAX_TITLE]
        body = args.get("body", "")[:MAX_BODY]
        nid = uuid.uuid4().hex[:8]
        _notes[nid] = {"id": nid, "title": title, "body": body, "created": datetime.now(timezone.utc).isoformat()}
        return {"id": nid, "message": "Note created"}
    if name == "read_note":
        nid = args.get("id", "")
        if not _validate_id(nid):
            return {"error": "Invalid note ID format"}
        note = _notes.get(nid)
        if not note:
            return {"error": "Note not found"}
        return {**note, "body": _scrub(note["body"])}
    if name == "list_notes":
        return {"notes": [{"id": n["id"], "title": n["title"]} for n in _notes.values()]}
    if name == "search_notes":
        q = args.get("query", "").lower()[:100]
        return {"results": [{"id": n["id"], "title": n["title"]} for n in _notes.values() if q in n["title"].lower() or q in n["body"].lower()]}
    return {"error": f"Unknown tool: {name}"}


def handle_jsonrpc(req):
    rid = req.get("id")
    method = req.get("method", "")
    params = req.get("params", {})
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "safe_notes", "version": "1.0.0"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        result = handle_call(params.get("name", ""), params.get("arguments", {}))
        return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(result)}], "isError": "error" in result}}
    if method == "notifications/initialized":
        return {}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {method}"}}


if __name__ == "__main__":
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_jsonrpc(req)
        if resp:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
