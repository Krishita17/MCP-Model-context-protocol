"""Tests for the provider abstraction layer."""

from providers.base import ToolSpec, ToolCall, Message, Provider


def test_tool_spec():
    spec = ToolSpec(name="add", description="Add numbers", input_schema={"type": "object"})
    assert spec.name == "add"


def test_tool_call():
    call = ToolCall(id="tc_1", name="add", arguments={"a": 1, "b": 2})
    assert call.name == "add"
    assert call.arguments == {"a": 1, "b": 2}


def test_message_helpers():
    sys = Message.system("You are helpful")
    assert sys.role == "system"
    usr = Message.user("Hello")
    assert usr.role == "user"
    asst = Message.assistant("Hi", tool_calls=[ToolCall(id="1", name="x", arguments={})])
    assert len(asst.tool_calls) == 1
    tool = Message.tool_result("1", "x", "result")
    assert tool.role == "tool"
    assert tool.tool_call_id == "1"


def test_build_provider_unknown():
    from providers import build_provider
    try:
        build_provider("nonexistent", model="x")
        assert False, "Should have raised"
    except (ValueError, KeyError):
        pass
