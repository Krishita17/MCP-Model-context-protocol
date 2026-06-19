"""Tests for environment checks."""

from environment import gather, stats, all_ok, Check


def test_gather():
    checks = gather()
    assert isinstance(checks, list)
    assert len(checks) > 0
    assert all(isinstance(c, Check) for c in checks)


def test_stats():
    s = stats()
    assert isinstance(s, dict)
    assert "attack_modules" in s
    assert "guardrails" in s


def test_all_ok_returns_bool():
    result = all_ok()
    assert isinstance(result, bool)
