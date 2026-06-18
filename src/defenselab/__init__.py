"""DefenseLab — Attack-vs-defense simulation and reporting for MCP security."""

__version__ = "0.1.0"

from defenselab.simulator import DefenseSimulator, SimulationResult
from defenselab.arena import SecurityArena, BattleResult
from defenselab.report import SecurityReportGenerator

__all__ = [
    "DefenseSimulator",
    "SimulationResult",
    "SecurityArena",
    "BattleResult",
    "SecurityReportGenerator",
]
