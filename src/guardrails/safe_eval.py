"""Safe expression evaluation via AST whitelist."""

from __future__ import annotations

import ast
import operator

class UnsafeExpression(Exception):
    """Raised when an expression contains disallowed nodes."""


_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _eval_node(node: ast.AST) -> float | int:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp):
        op = type(node.op)
        if op not in _OPS:
            raise UnsafeExpression(f"Disallowed operator: {op.__name__}")
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        if op is ast.Pow and right > 1000:
            raise UnsafeExpression("Exponent too large")
        return _OPS[op](left, right)
    if isinstance(node, ast.UnaryOp):
        op = type(node.op)
        if op not in _OPS:
            raise UnsafeExpression(f"Disallowed unary operator: {op.__name__}")
        return _OPS[op](_eval_node(node.operand))
    raise UnsafeExpression(f"Disallowed node: {type(node).__name__}")


def safe_eval(expr: str) -> float | int:
    """Evaluate a math expression safely (numbers and +-*/% ** only)."""
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpression(f"Syntax error: {exc}") from exc
    return _eval_node(tree)
