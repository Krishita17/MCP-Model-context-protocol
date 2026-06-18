"""Tests for the security arena."""

from defenselab.arena import SecurityArena, BattleResult, TournamentResult


def test_arena_init():
    arena = SecurityArena()
    assert arena is not None


def test_arena_battle():
    arena = SecurityArena()
    arena.configure_attacker(attack_types=["description_injection"])
    arena.configure_defender(layers_enabled=["static_scanner", "policy_engine"])
    result = arena.battle()
    assert isinstance(result, BattleResult)
    assert len(result.rounds) > 0


def test_arena_tournament():
    arena = SecurityArena()
    result = arena.tournament()
    assert isinstance(result, TournamentResult)
    assert len(result.battles) > 0
