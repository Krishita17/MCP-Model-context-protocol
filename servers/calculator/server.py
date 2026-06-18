"""Calculator MCP Server — a deliberately simple server for attack/defense demos.

Exposes basic arithmetic tools via the Model Context Protocol.
Can be run standalone:  python -m servers.calculator.server
"""

from __future__ import annotations

import json
import math
import sys
from typing import Any


TOOLS = [
    {
        "name": "add",
        "description": "Add two numbers together and return the result.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "First operand"},
                "b": {"type": "number", "description": "Second operand"},
            },
            "required": ["a", "b"],
        },
    },
    {
        "name": "subtract",
        "description": "Subtract b from a and return the result.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
            },
            "required": ["a", "b"],
        },
    },
    {
        "name": "multiply",
        "description": "Multiply two numbers and return the result.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
            },
            "required": ["a", "b"],
        },
    },
    {
        "name": "divide",
        "description": "Divide a by b. Returns an error if b is zero.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
            },
            "required": ["a", "b"],
        },
    },
    {
        "name": "power",
        "description": "Raise a to the power of b.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "Base"},
                "b": {"type": "number", "description": "Exponent"},
            },
            "required": ["a", "b"],
        },
    },
    {
        "name": "sqrt",
        "description": "Return the square root of a number.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "Non-negative number"},
            },
            "required": ["a"],
        },
    },
]


def handle_call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    a = arguments.get("a", 0)
    b = arguments.get("b", 0)

    match tool_name:
        case "add":
            return {"result": a + b}
        case "subtract":
            return {"result": a - b}
        case "multiply":
            return {"result": a * b}
        case "divide":
            if b == 0:
                return {"error": "Division by zero"}
            return {"result": a / b}
        case "power":
            return {"result": math.pow(a, b)}
        case "sqrt":
            if a < 0:
                return {"error": "Cannot take square root of negative number"}
            return {"result": math.sqrt(a)}
        case _:
            return {"error": f"Unknown tool: {tool_name}"}


def _jsonrpc_response(id_: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _jsonrpc_error(id_: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def handle_jsonrpc(request: dict) -> dict:
    """Handle a JSON-RPC 2.0 request for MCP."""
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "initialize":
        return _jsonrpc_response(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "calculator", "version": "1.0.0"},
        })
    elif method == "tools/list":
        return _jsonrpc_response(req_id, {"tools": TOOLS})
    elif method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        result = handle_call(name, args)
        if "error" in result:
            return _jsonrpc_response(req_id, {
                "content": [{"type": "text", "text": result["error"]}],
                "isError": True,
            })
        return _jsonrpc_response(req_id, {
            "content": [{"type": "text", "text": json.dumps(result)}],
        })
    elif method == "notifications/initialized":
        return {}
    else:
        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def main() -> None:
    """Run as a stdio MCP server."""
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
