"""Tests for the calculator MCP server."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from servers.calculator.server import handle_call, handle_jsonrpc, TOOLS


def test_add():
    assert handle_call("add", {"a": 2, "b": 3}) == {"result": 5}


def test_subtract():
    assert handle_call("subtract", {"a": 10, "b": 3}) == {"result": 7}


def test_multiply():
    assert handle_call("multiply", {"a": 4, "b": 5}) == {"result": 20}


def test_divide():
    assert handle_call("divide", {"a": 10, "b": 2}) == {"result": 5.0}


def test_divide_by_zero():
    result = handle_call("divide", {"a": 1, "b": 0})
    assert "error" in result


def test_power():
    assert handle_call("power", {"a": 2, "b": 10}) == {"result": 1024.0}


def test_sqrt():
    assert handle_call("sqrt", {"a": 16}) == {"result": 4.0}


def test_sqrt_negative():
    result = handle_call("sqrt", {"a": -1})
    assert "error" in result


def test_tools_list():
    assert len(TOOLS) == 6


def test_jsonrpc_initialize():
    resp = handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp["result"]["serverInfo"]["name"] == "calculator"


def test_jsonrpc_tools_list():
    resp = handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert len(resp["result"]["tools"]) == 6


def test_jsonrpc_tool_call():
    resp = handle_jsonrpc({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "add", "arguments": {"a": 5, "b": 3}},
    })
    assert '"result": 8' in resp["result"]["content"][0]["text"]
