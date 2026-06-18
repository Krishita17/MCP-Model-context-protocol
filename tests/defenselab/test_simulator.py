"""Tests for the defense lab simulator."""

import pytest

from defenselab.simulator import DefenseSimulator, SimulationResult, MatrixResult


@pytest.fixture
def simulator():
    return DefenseSimulator()


def test_simulator_init(simulator):
    assert simulator is not None
    assert simulator.scanner is not None
    assert simulator.monitor is not None


def test_run_simulation(simulator):
    result = simulator.run_simulation("description_injection")
    assert isinstance(result, SimulationResult)
    assert result.attack_name == "description_injection"
    assert isinstance(result.layers_triggered, list)
    assert isinstance(result.passed_through, bool)


def test_simulation_catches_injection(simulator):
    result = simulator.run_simulation("description_injection")
    assert len(result.layers_triggered) > 0
    assert "static_scanner" in result.layers_triggered


def test_simulate_unknown_attack(simulator):
    with pytest.raises(ValueError, match="Unknown attack type"):
        simulator.run_simulation("nonexistent_attack")


def test_run_full_matrix(simulator):
    matrix = simulator.run_full_matrix()
    assert isinstance(matrix, MatrixResult)
    assert matrix.total_attacks > 0
    assert matrix.total_blocked + matrix.total_passed == matrix.total_attacks


def test_matrix_blocks_most_attacks(simulator):
    matrix = simulator.run_full_matrix()
    block_rate = matrix.total_blocked / max(matrix.total_attacks, 1)
    assert block_rate > 0.3, "Defense should block at least 30% of attacks"
