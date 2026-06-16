"""FAIR (Factor Analysis of Information Risk) model for MCP attack exposure."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Frequency(str, Enum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    VERY_LOW = "very_low"


class Magnitude(str, Enum):
    CATASTROPHIC = "catastrophic"
    SEVERE = "severe"
    SIGNIFICANT = "significant"
    MODERATE = "moderate"
    MINOR = "minor"


FREQUENCY_VALUES = {
    Frequency.VERY_HIGH: 100,
    Frequency.HIGH: 50,
    Frequency.MODERATE: 10,
    Frequency.LOW: 2,
    Frequency.VERY_LOW: 0.5,
}

MAGNITUDE_RANGES = {
    Magnitude.CATASTROPHIC: (10_000_000, 100_000_000),
    Magnitude.SEVERE: (1_000_000, 10_000_000),
    Magnitude.SIGNIFICANT: (100_000, 1_000_000),
    Magnitude.MODERATE: (10_000, 100_000),
    Magnitude.MINOR: (1_000, 10_000),
}


@dataclass
class ThreatScenario:
    attack_class: str
    threat_event_frequency: Frequency
    vulnerability: float
    primary_loss_magnitude: Magnitude
    secondary_loss_magnitude: Magnitude
    description: str

    @property
    def loss_event_frequency(self) -> float:
        return FREQUENCY_VALUES[self.threat_event_frequency] * self.vulnerability

    @property
    def primary_loss_range(self) -> tuple[float, float]:
        return MAGNITUDE_RANGES[self.primary_loss_magnitude]

    @property
    def secondary_loss_range(self) -> tuple[float, float]:
        return MAGNITUDE_RANGES[self.secondary_loss_magnitude]

    @property
    def annualized_loss_expectancy(self) -> tuple[float, float]:
        freq = self.loss_event_frequency
        p_low, p_high = self.primary_loss_range
        s_low, s_high = self.secondary_loss_range
        return (freq * (p_low + s_low), freq * (p_high + s_high))

    def to_dict(self) -> dict[str, Any]:
        ale_low, ale_high = self.annualized_loss_expectancy
        return {
            "attack_class": self.attack_class,
            "description": self.description,
            "threat_event_frequency": self.threat_event_frequency.value,
            "vulnerability": self.vulnerability,
            "loss_event_frequency": round(self.loss_event_frequency, 2),
            "primary_loss": self.primary_loss_magnitude.value,
            "secondary_loss": self.secondary_loss_magnitude.value,
            "ale_low": f"${ale_low:,.0f}",
            "ale_high": f"${ale_high:,.0f}",
        }


def build_default_scenarios() -> list[ThreatScenario]:
    return [
        ThreatScenario(
            attack_class="description_injection",
            threat_event_frequency=Frequency.HIGH,
            vulnerability=0.6,
            primary_loss_magnitude=Magnitude.SEVERE,
            secondary_loss_magnitude=Magnitude.SIGNIFICANT,
            description="Hidden instructions in tool descriptions causing data exfiltration",
        ),
        ThreatScenario(
            attack_class="tool_shadowing",
            threat_event_frequency=Frequency.MODERATE,
            vulnerability=0.4,
            primary_loss_magnitude=Magnitude.SEVERE,
            secondary_loss_magnitude=Magnitude.MODERATE,
            description="Malicious tool impersonating legitimate tool to intercept data",
        ),
        ThreatScenario(
            attack_class="rug_pull",
            threat_event_frequency=Frequency.LOW,
            vulnerability=0.8,
            primary_loss_magnitude=Magnitude.CATASTROPHIC,
            secondary_loss_magnitude=Magnitude.SEVERE,
            description="Post-approval behavioral mutation enabling persistent compromise",
        ),
        ThreatScenario(
            attack_class="return_value_poisoning",
            threat_event_frequency=Frequency.HIGH,
            vulnerability=0.5,
            primary_loss_magnitude=Magnitude.SIGNIFICANT,
            secondary_loss_magnitude=Magnitude.MODERATE,
            description="Malicious payloads in tool outputs manipulating agent context",
        ),
        ThreatScenario(
            attack_class="cross_tool_escalation",
            threat_event_frequency=Frequency.MODERATE,
            vulnerability=0.7,
            primary_loss_magnitude=Magnitude.SEVERE,
            secondary_loss_magnitude=Magnitude.SIGNIFICANT,
            description="Chained benign tool calls achieving compound malicious outcomes",
        ),
    ]
