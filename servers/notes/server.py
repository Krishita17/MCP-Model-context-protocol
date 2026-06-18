"""Notes MCP Server — in-memory note storage for attack/defense demos.

Provides CRUD operations on notes via MCP protocol.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any


_notes: dict[str, dict[str, str]] = {}

TOOLS = [
    {
        "name": "create_note",
        "description": "Create a new note with a title and body. Returns the note ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Note title"},
                "body": {"type": "string", "description": "Note content"},
            },
            "required": ["title", "body"],
        },
    },
    {
        "name": "read_note",
        "description": "Read a note by its ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Note ID"},
            },
            "required": ["id"],
        },
    },
    {
        "name": "list_notes",
        "description": "List all stored notes with their IDs and titles.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "delete_note",
        "description": "Delete a note by its ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Note ID"},
            },
            "required": ["id"],
        },
    },
    {
        "name": "search_notes",
        "description": "Search notes by keyword in title or body.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword"},
            },
            "required": ["query"],
        },
    },
]


def handle_call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    match tool_name:
        case "create_note":
            note_id = uuid.uuid4().hex[:8]
            _notes[note_id] = {
                "id": note_id,
                "title": arguments["title"],
                "body": arguments["body"],
                "created": datetime.now(timezone.utc).isoformat(),
            }
            return {"id": note_id, "message": "Note created"}
        case "read_note":
            note = _notes.get(arguments["id"])
            if not note:
                return {"error": f"Note {arguments['id']} not found"}
            return note
        case "list_notes":
            return {"notes": [{"id": n["id"], "title": n["title"]} for n in _notes.values()]}
        case "delete_note":
            if arguments["id"] not in _notes:
                return {"error": f"Note {arguments['id']} not found"}
            del _notes[arguments["id"]]
            return {"message": "Note deleted"}
        case "search_notes":
            q = arguments["query"].lower()
            matches = [
                {"id": n["id"], "title": n["title"]}
                for n in _notes.values()
                if q in n["title"].lower() or q in n["body"].lower()
            ]
            return {"results": matches}
        case _:
            return {"error": f"Unknown tool: {tool_name}"}


def handle_jsonrpc(request: dict) -> dict:
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "notes", "version": "1.0.0"},
        }}
    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    elif method == "tools/call":
        result = handle_call(params.get("name", ""), params.get("arguments", {}))
        is_error = "error" in result
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": json.dumps(result)}],
            "isError": is_error,
        }}
    elif method == "notifications/initialized":
        return {}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown: {method}"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle_jsonrpc(request)
        if response:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
