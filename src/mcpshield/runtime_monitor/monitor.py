"""Runtime behavioral monitor — Layer 2 of MCPShield."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MonitorDecision(str, Enum):
    ALLOW = "allow"
    THROTTLE = "throttle"
    BLOCK = "block"
    ESCALATE = "escalate_to_human"


class AnomalyType(str, Enum):
    RATE_ANOMALY = "rate_anomaly"
    DATA_FLOW_VIOLATION = "data_flow_violation"
    BEHAVIORAL_DEVIATION = "behavioral_deviation"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    UNAUTHORIZED_DESTINATION = "unauthorized_destination"


@dataclass
class ToolInvocation:
    tool_name: str
    timestamp: float
    input_data: dict[str, Any]
    output_data: dict[str, Any] | None = None
    caller_context: str = ""
    session_id: str = ""


@dataclass
class MonitorAlert:
    anomaly_type: AnomalyType
    decision: MonitorDecision
    tool_name: str
    description: str
    anomaly_score: float
    evidence: dict[str, Any]
    timestamp: float = field(default_factory=time.time)


@dataclass
class BehavioralProfile:
    tool_name: str
    avg_calls_per_minute: float = 0.0
    typical_input_size: float = 0.0
    typical_output_size: float = 0.0
    common_callers: list[str] = field(default_factory=list)
    data_flow_destinations: list[str] = field(default_factory=list)
    observation_count: int = 0


SENSITIVE_PATTERNS = [
    r"(?i)(api[_-]?key|secret|token|password|credential|private[_-]?key)",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"\b(?:sk|pk|rk)-[a-zA-Z0-9]{20,}\b",
    r"(?i)(bearer\s+[a-zA-Z0-9._~+/=-]+)",
]


class RuntimeMonitor:
    def __init__(
        self,
        rate_limit_per_minute: int = 60,
        anomaly_threshold: float = 0.7,
    ) -> None:
        self.rate_limit = rate_limit_per_minute
        self.anomaly_threshold = anomaly_threshold
        self.profiles: dict[str, BehavioralProfile] = {}
        self.invocation_history: dict[str, list[float]] = defaultdict(list)
        self.alerts: list[MonitorAlert] = []
        self.log = logger.bind(component="runtime_monitor")

    def record_invocation(self, invocation: ToolInvocation) -> MonitorDecision:
        alerts: list[MonitorAlert] = []

        rate_alert = self._check_rate(invocation)
        if rate_alert:
            alerts.append(rate_alert)

        data_alerts = self._check_data_flow(invocation)
        alerts.extend(data_alerts)

        behavioral_alert = self._check_behavioral_deviation(invocation)
        if behavioral_alert:
            alerts.append(behavioral_alert)

        self._update_profile(invocation)
        self.invocation_history[invocation.tool_name].append(invocation.timestamp)
        self.alerts.extend(alerts)

        if not alerts:
            return MonitorDecision.ALLOW

        max_severity = max(alerts, key=lambda a: a.anomaly_score)
        return max_severity.decision

    def _check_rate(self, invocation: ToolInvocation) -> MonitorAlert | None:
        history = self.invocation_history[invocation.tool_name]
        cutoff = invocation.timestamp - 60.0
        recent = [t for t in history if t > cutoff]

        if len(recent) >= self.rate_limit:
            return MonitorAlert(
                anomaly_type=AnomalyType.RATE_ANOMALY,
                decision=MonitorDecision.THROTTLE,
                tool_name=invocation.tool_name,
                description=f"Rate limit exceeded: {len(recent)} calls in last 60s",
                anomaly_score=0.8,
                evidence={"calls_per_minute": len(recent), "limit": self.rate_limit},
            )
        return None

    def _check_data_flow(self, invocation: ToolInvocation) -> list[MonitorAlert]:
        import re
        alerts: list[MonitorAlert] = []
        input_str = str(invocation.input_data)

        for pattern in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, input_str)
            if matches:
                alerts.append(MonitorAlert(
                    anomaly_type=AnomalyType.SENSITIVE_DATA_EXPOSURE,
                    decision=MonitorDecision.BLOCK,
                    tool_name=invocation.tool_name,
                    description=f"Sensitive data detected in tool input: {len(matches)} matches",
                    anomaly_score=0.95,
                    evidence={"pattern_matches": len(matches), "sample": str(matches[:2])},
                ))
                break

        return alerts

    def _check_behavioral_deviation(self, invocation: ToolInvocation) -> MonitorAlert | None:
        profile = self.profiles.get(invocation.tool_name)
        if profile is None or profile.observation_count < 10:
            return None

        input_size = len(str(invocation.input_data))
        if profile.typical_input_size > 0:
            size_ratio = input_size / profile.typical_input_size
            if size_ratio > 5.0 or size_ratio < 0.1:
                return MonitorAlert(
                    anomaly_type=AnomalyType.BEHAVIORAL_DEVIATION,
                    decision=MonitorDecision.ESCALATE,
                    tool_name=invocation.tool_name,
                    description=f"Input size deviation: {size_ratio:.1f}x typical",
                    anomaly_score=min(0.9, size_ratio / 10),
                    evidence={
                        "input_size": input_size,
                        "typical_size": profile.typical_input_size,
                        "ratio": round(size_ratio, 2),
                    },
                )
        return None

    def _update_profile(self, invocation: ToolInvocation) -> None:
        name = invocation.tool_name
        if name not in self.profiles:
            self.profiles[name] = BehavioralProfile(tool_name=name)

        p = self.profiles[name]
        input_size = len(str(invocation.input_data))
        n = p.observation_count
        p.typical_input_size = (p.typical_input_size * n + input_size) / (n + 1)
        p.observation_count += 1

        if invocation.caller_context and invocation.caller_context not in p.common_callers:
            p.common_callers.append(invocation.caller_context)

    def get_profile(self, tool_name: str) -> BehavioralProfile | None:
        return self.profiles.get(tool_name)

    def get_alerts(self, tool_name: str | None = None) -> list[MonitorAlert]:
        if tool_name:
            return [a for a in self.alerts if a.tool_name == tool_name]
        return list(self.alerts)
