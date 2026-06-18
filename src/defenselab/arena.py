"""Security Arena — interactive attack-vs-defense battle simulations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from defenselab.simulator import DefenseSimulator, SimulationResult
from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpshield.static_analysis.scanner import StaticScanner
from mcpshield.runtime_monitor.monitor import RuntimeMonitor
from mcpshield.policy_engine.engine import PolicyEngine, PolicyRule, PolicyAction

logger = structlog.get_logger()


@dataclass
class AttackerConfig:
    """Red-team attacker configuration."""

    attack_types: list[str] = field(default_factory=list)
    variants: dict[str, list[str]] = field(default_factory=dict)
    evasion_level: int = 1  # 1 = basic, 2 = moderate, 3 = advanced


@dataclass
class DefenderConfig:
    """Blue-team defender configuration."""

    layers_enabled: list[str] = field(
        default_factory=lambda: [
            "static_scanner",
            "runtime_monitor",
            "policy_engine",
            "crypto_verification",
        ]
    )
    policy_strictness: str = "medium"  # low | medium | high
    crypto_required: bool = True


@dataclass
class RoundResult:
    """Outcome of a single battle round."""

    round_number: int
    attack_type: str
    attack_variant: str
    attacker_won: bool
    layers_triggered: list[str]
    detection_time_ms: float
    findings: list[str]


@dataclass
class BattleResult:
    """Full battle result between one attacker config and one defender config."""

    attacker: AttackerConfig
    defender: DefenderConfig
    rounds: list[RoundResult] = field(default_factory=list)
    attacker_score: int = 0
    defender_score: int = 0

    @property
    def winner(self) -> str:
        if self.defender_score > self.attacker_score:
            return "defender"
        if self.attacker_score > self.defender_score:
            return "attacker"
        return "draw"

    @property
    def total_rounds(self) -> int:
        return len(self.rounds)


@dataclass
class TournamentResult:
    """Aggregate results of all-vs-all tournament."""

    battles: list[BattleResult] = field(default_factory=list)
    overall_attacker_wins: int = 0
    overall_defender_wins: int = 0
    overall_draws: int = 0

    @property
    def defender_win_rate(self) -> float:
        total = len(self.battles)
        return self.overall_defender_wins / total if total else 0.0


# ---------------------------------------------------------------------------
# Preset strictness policies
# ---------------------------------------------------------------------------

_STRICTNESS_RULES: dict[str, list[PolicyRule]] = {
    "low": [
        PolicyRule(
            rule_id="low_block_malicious",
            description="Block clearly malicious tools",
            condition={"has_tag": "malicious"},
            action=PolicyAction.BLOCK,
            priority=100,
        ),
    ],
    "medium": [
        PolicyRule(
            rule_id="med_block_malicious",
            description="Block malicious tools",
            condition={"has_tag": "malicious"},
            action=PolicyAction.BLOCK,
            priority=100,
        ),
        PolicyRule(
            rule_id="med_approve_suspicious",
            description="Require approval for suspicious tools",
            condition={"has_tag": "suspicious"},
            action=PolicyAction.REQUEST_APPROVAL,
            priority=80,
        ),
        PolicyRule(
            rule_id="med_block_exfil",
            description="Block network exfiltration",
            condition={"requires_capability": "network_exfil"},
            action=PolicyAction.BLOCK,
            priority=90,
        ),
    ],
    "high": [
        PolicyRule(
            rule_id="high_block_malicious",
            description="Block malicious tools",
            condition={"has_tag": "malicious"},
            action=PolicyAction.BLOCK,
            priority=100,
        ),
        PolicyRule(
            rule_id="high_block_suspicious",
            description="Block suspicious tools",
            condition={"has_tag": "suspicious"},
            action=PolicyAction.BLOCK,
            priority=95,
        ),
        PolicyRule(
            rule_id="high_block_exfil",
            description="Block network exfiltration",
            condition={"requires_capability": "network_exfil"},
            action=PolicyAction.BLOCK,
            priority=90,
        ),
        PolicyRule(
            rule_id="high_block_exec",
            description="Block code execution capabilities",
            condition={"requires_capability": "code_execution"},
            action=PolicyAction.BLOCK,
            priority=90,
        ),
        PolicyRule(
            rule_id="high_approve_sensitive",
            description="Require approval for sensitive data access",
            condition={"data_classification": "sensitive"},
            action=PolicyAction.REQUEST_APPROVAL,
            priority=80,
        ),
    ],
}


class SecurityArena:
    """Orchestrates head-to-head attack-vs-defense battles."""

    def __init__(self) -> None:
        self._attacker: AttackerConfig = AttackerConfig()
        self._defender: DefenderConfig = DefenderConfig()
        self.log = logger.bind(component="security_arena")

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_attacker(
        self,
        attack_types: list[str] | None = None,
        variants: dict[str, list[str]] | None = None,
        evasion_level: int = 1,
    ) -> None:
        self._attacker = AttackerConfig(
            attack_types=attack_types or list(ATTACK_REGISTRY),
            variants=variants or {},
            evasion_level=max(1, min(evasion_level, 3)),
        )

    def configure_defender(
        self,
        layers_enabled: list[str] | None = None,
        policy_strictness: str = "medium",
        crypto_required: bool = True,
    ) -> None:
        self._defender = DefenderConfig(
            layers_enabled=layers_enabled
            or [
                "static_scanner",
                "runtime_monitor",
                "policy_engine",
                "crypto_verification",
            ],
            policy_strictness=policy_strictness,
            crypto_required=crypto_required,
        )

    # ------------------------------------------------------------------
    # Battle execution
    # ------------------------------------------------------------------

    def battle(self) -> BattleResult:
        """Run configured attacker against configured defender."""
        simulator = self._build_simulator(self._defender)
        result = BattleResult(attacker=self._attacker, defender=self._defender)

        round_num = 0
        for attack_type in self._attacker.attack_types:
            variants = self._attacker.variants.get(attack_type, ["default"])
            chosen = variants[: self._attacker.evasion_level]
            for variant in chosen:
                round_num += 1
                sim = simulator.run_simulation(attack_type, variant)
                attacker_won = sim.passed_through
                rr = RoundResult(
                    round_number=round_num,
                    attack_type=attack_type,
                    attack_variant=variant,
                    attacker_won=attacker_won,
                    layers_triggered=sim.layers_triggered,
                    detection_time_ms=sim.detection_time_ms,
                    findings=sim.findings,
                )
                result.rounds.append(rr)
                if attacker_won:
                    result.attacker_score += 1
                else:
                    result.defender_score += 1

        return result

    def tournament(self) -> TournamentResult:
        """Run all attack types and variants against all defense configurations."""
        tournament = TournamentResult()
        all_attack_types = list(ATTACK_REGISTRY)

        for strictness in ("low", "medium", "high"):
            for crypto in (True, False):
                self.configure_attacker(
                    attack_types=all_attack_types, evasion_level=3
                )
                self.configure_defender(
                    policy_strictness=strictness, crypto_required=crypto
                )
                battle_result = self.battle()
                tournament.battles.append(battle_result)

                if battle_result.winner == "defender":
                    tournament.overall_defender_wins += 1
                elif battle_result.winner == "attacker":
                    tournament.overall_attacker_wins += 1
                else:
                    tournament.overall_draws += 1

        return tournament

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_simulator(self, defender: DefenderConfig) -> DefenseSimulator:
        scanner = (
            StaticScanner()
            if "static_scanner" in defender.layers_enabled
            else None
        )
        monitor = (
            RuntimeMonitor()
            if "runtime_monitor" in defender.layers_enabled
            else None
        )
        policy = self._build_policy_engine(defender)
        enable_crypto = (
            defender.crypto_required
            and "crypto_verification" in defender.layers_enabled
        )

        return DefenseSimulator(
            static_scanner=scanner,
            runtime_monitor=monitor,
            policy_engine=policy,
            enable_crypto=enable_crypto,
        )

    @staticmethod
    def _build_policy_engine(defender: DefenderConfig) -> PolicyEngine | None:
        if "policy_engine" not in defender.layers_enabled:
            return None
        engine = PolicyEngine()
        rules = _STRICTNESS_RULES.get(defender.policy_strictness, _STRICTNESS_RULES["medium"])
        for rule in rules:
            engine.add_rule(rule)
        return engine
