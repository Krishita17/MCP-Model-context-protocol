"""Tests for the automation engine."""

import pytest
from automation.engine import AutomationEngine, PipelineResult, StepStatus


def test_engine_init():
    engine = AutomationEngine()
    assert engine is not None


def test_builtin_pipelines_registered():
    engine = AutomationEngine()
    names = engine.available_pipelines
    assert "full_security_audit" in names
    assert "quick_scan" in names


def test_run_quick_scan():
    engine = AutomationEngine()
    result = engine.run_pipeline("quick_scan")
    assert isinstance(result, PipelineResult)
    assert result.pipeline_name == "quick_scan"
    assert len(result.steps) > 0


def test_run_unknown_pipeline():
    engine = AutomationEngine()
    with pytest.raises(ValueError, match="Unknown pipeline"):
        engine.run_pipeline("nonexistent")


def test_custom_pipeline():
    engine = AutomationEngine()
    engine.register_pipeline("test_pipe", [
        ("step1", lambda ctx: "hello"),
    ])
    result = engine.run_pipeline("test_pipe")
    assert result.success
    assert result.steps[0].status == StepStatus.SUCCESS
