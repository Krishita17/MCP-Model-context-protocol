"""Tests for the filesystem MCP server."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from servers.filesystem.server import handle_call, SANDBOX


def test_write_and_read():
    handle_call("write_file", {"path": "test.txt", "content": "hello world"})
    result = handle_call("read_file", {"path": "test.txt"})
    assert result["content"] == "hello world"


def test_list_directory():
    handle_call("write_file", {"path": "listing_test.txt", "content": "x"})
    result = handle_call("list_directory", {"path": "."})
    names = [e["name"] for e in result["entries"]]
    assert "listing_test.txt" in names


def test_delete_file():
    handle_call("write_file", {"path": "to_delete.txt", "content": "bye"})
    result = handle_call("delete_file", {"path": "to_delete.txt"})
    assert "Deleted" in result["message"]


def test_path_traversal_blocked():
    result = handle_call("read_file", {"path": "../../etc/passwd"})
    assert "error" in result
    assert "traversal" in result["error"].lower() or "not found" in result["error"].lower()


def test_read_nonexistent():
    result = handle_call("read_file", {"path": "does_not_exist.txt"})
    assert "error" in result
