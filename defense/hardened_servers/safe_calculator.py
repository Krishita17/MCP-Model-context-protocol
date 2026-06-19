"""Hardened calculator — uses safe_eval instead of eval(), blocks code injection."""

import ast
import json
import math
import operator
import sys

ALLOWED_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

ALLOWED_FUNCS = {"sqrt": math.sqrt, "abs": abs, "round": round}


def safe_eval(expr: str) -> float:
    tree = ast.parse(expr, mode="eval")
    return _eval_node(tree.body)


def _eval_node(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in ALLOWED_OPS:
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        return ALLOWED_OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in ALLOWED_OPS:
        return ALLOWED_OPS[type(node.op)](_eval_node(node.operand))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ALLOWED_FUNCS:
            args = [_eval_node(a) for a in node.args]
            return ALLOWED_FUNCS[node.func.id](*args)
    raise ValueError(f"Unsafe expression node: {ast.dump(node)}")


TOOLS = [
    {
        "name": "calculate",
        "description": "Evaluate a mathematical expression safely. Supports +, -, *, /, **, sqrt, abs, round.",
        "inputSchema": {
            "type": "object",
            "properties": {"expression": {"type": "string"}},
            "required": ["expression"],
        },
    },
]


def handle_call(name, args):
    if name == "calculate":
        try:
            result = safe_eval(args["expression"])
            return {"result": result}
        except (ValueError, ZeroDivisionError, TypeError) as e:
            return {"error": str(e)}
    return {"error": f"Unknown tool: {name}"}


def handle_jsonrpc(req):
    rid = req.get("id")
    method = req.get("method", "")
    params = req.get("params", {})
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "safe_calculator", "version": "1.0.0"},
        }}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        result = handle_call(params.get("name", ""), params.get("arguments", {}))
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": json.dumps(result)}],
            "isError": "error" in result,
        }}
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
