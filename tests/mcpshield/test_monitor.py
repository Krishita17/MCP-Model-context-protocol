"""Tests for MCPShield runtime monitor."""

import time

import pytest

from mcpshield.runtime_monitor.monitor import (
    RuntimeMonitor,
    MonitorDecision,
    ToolInvocation,
)


@pytest.fixture
def monitor():
    return RuntimeMonitor(rate_limit_per_minute=5, anomaly_threshold=0.7)


class TestRuntimeMonitor:
    def test_normal_invocation_allowed(self, monitor):
        inv = ToolInvocation(
            tool_name="calculator",
            timestamp=time.time(),
            input_data={"a": 1, "b": 2, "op": "+"},
        )
        decision = monitor.record_invocation(inv)
        assert decision == MonitorDecision.ALLOW

    def test_rate_limiting(self, monitor):
        now = time.time()
        for i in range(6):
            inv = ToolInvocation(
                tool_name="calculator",
                timestamp=now + i * 0.1,
                input_data={"a": i},
            )
            decision = monitor.record_invocation(inv)

        assert decision == MonitorDecision.THROTTLE

    def test_sensitive_data_blocked(self, monitor):
        inv = ToolInvocation(
            tool_name="http_request",
            timestamp=time.time(),
            input_data={
                "url": "https://api.example.com",
                "headers": {"Authorization": "Bearer sk-abc123def456ghi789"},
            },
        )
        decision = monitor.record_invocation(inv)
        assert decision == MonitorDecision.BLOCK

    def test_profile_building(self, monitor):
        for i in range(15):
            inv = ToolInvocation(
                tool_name="query",
                timestamp=time.time() + i,
                input_data={"q": "x" * 100},
            )
            monitor.record_invocation(inv)

        profile = monitor.get_profile("query")
        assert profile is not None
        assert profile.observation_count == 15
        assert profile.typical_input_size > 0

    def test_alerts_collected(self, monitor):
        inv = ToolInvocation(
            tool_name="sender",
            timestamp=time.time(),
            input_data={"api_key": "sk-secret-token-12345678901234567890"},
        )
        monitor.record_invocation(inv)
        alerts = monitor.get_alerts("sender")
        assert len(alerts) > 0
