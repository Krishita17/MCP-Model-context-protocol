"""Automation engine — named pipelines for orchestrating security workflows."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

from defenselab.simulator import DefenseSimulator, MatrixResult, SimulationResult
from defenselab.report import SecurityReportGenerator
from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpshield.static_analysis.scanner import StaticScanner
from mcpshield.runtime_monitor.monitor import RuntimeMonitor
from mcpshield.policy_engine.engine import PolicyEngine
from cryptomcp.signing.signer import ToolSigner, ToolVerifier, compute_tool_hash
from cryptomcp.signing.keys import generate_key_pair
from cryptomcp.merkle.audit_log import MerkleAuditLog

logger = structlog.get_logger()


class StepStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"


@dataclass
class StepResult:
    """Result of one pipeline step."""

    step_name: str
    status: StepStatus
    duration_ms: float
    output: Any = None
    error: str | None = None


@dataclass
class PipelineResult:
    """Aggregate result of an entire pipeline run."""

    pipeline_name: str
    steps: list[StepResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    success: bool = True

    @property
    def failed_steps(self) -> list[StepResult]:
        return [s for s in self.steps if s.status == StepStatus.FAILURE]


# ---------------------------------------------------------------------------
# Step type: a callable that takes context dict and returns output
# ---------------------------------------------------------------------------
PipelineStep = Callable[[dict[str, Any]], Any]


class AutomationEngine:
    """Register and execute named automation pipelines."""

    def __init__(self) -> None:
        self._pipelines: dict[str, list[tuple[str, PipelineStep]]] = {}
        self.log = logger.bind(component="automation_engine")
        self._register_builtin_pipelines()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_pipeline(
        self,
        name: str,
        steps: list[tuple[str, PipelineStep]],
    ) -> None:
        """Register a named pipeline as a list of (step_name, callable) tuples."""
        self._pipelines[name] = steps
        self.log.info("pipeline_registered", name=name, step_count=len(steps))

    def run_pipeline(
        self,
        name: str,
        context: dict[str, Any] | None = None,
    ) -> PipelineResult:
        """Execute a registered pipeline by name."""
        if name not in self._pipelines:
            raise ValueError(
                f"Unknown pipeline '{name}'. "
                f"Available: {list(self._pipelines)}"
            )

        ctx = context or {}
        result = PipelineResult(pipeline_name=name)
        pipeline_start = time.monotonic()

        for step_name, step_fn in self._pipelines[name]:
            step_start = time.monotonic()
            try:
                output = step_fn(ctx)
                elapsed = (time.monotonic() - step_start) * 1000
                ctx[step_name] = output
                result.steps.append(
                    StepResult(
                        step_name=step_name,
                        status=StepStatus.SUCCESS,
                        duration_ms=round(elapsed, 3),
                        output=output,
                    )
                )
            except Exception as exc:
                elapsed = (time.monotonic() - step_start) * 1000
                self.log.error(
                    "pipeline_step_failed",
                    pipeline=name,
                    step=step_name,
                    error=str(exc),
                )
                result.steps.append(
                    StepResult(
                        step_name=step_name,
                        status=StepStatus.FAILURE,
                        duration_ms=round(elapsed, 3),
                        error=str(exc),
                    )
                )
                result.success = False
                break  # stop pipeline on first failure

        result.total_duration_ms = round(
            (time.monotonic() - pipeline_start) * 1000, 3
        )
        return result

    @property
    def available_pipelines(self) -> list[str]:
        return list(self._pipelines)

    # ------------------------------------------------------------------
    # Built-in pipelines
    # ------------------------------------------------------------------

    def _register_builtin_pipelines(self) -> None:
        self.register_pipeline("full_security_audit", [
            ("scan", _step_full_scan),
            ("attack_matrix", _step_attack_matrix),
            ("report_markdown", _step_generate_markdown_report),
            ("report_json", _step_generate_json_report),
        ])

        self.register_pipeline("quick_scan", [
            ("scan", _step_quick_scan),
            ("report_markdown", _step_generate_markdown_report),
        ])

        self.register_pipeline("crypto_verify_all", [
            ("generate_keys", _step_generate_keys),
            ("sign_tools", _step_sign_sample_tools),
            ("verify_tools", _step_verify_signed_tools),
            ("audit_log", _step_audit_log_check),
        ])

        self.register_pipeline("compliance_check", [
            ("scan", _step_full_scan),
            ("attack_matrix", _step_attack_matrix),
            ("compliance_report", _step_compliance_report),
        ])


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------

def _step_full_scan(ctx: dict[str, Any]) -> list[SimulationResult]:
    """Run full defense matrix simulation."""
    sim = DefenseSimulator()
    matrix = sim.run_full_matrix()
    ctx["_matrix"] = matrix
    return matrix.results


def _step_quick_scan(ctx: dict[str, Any]) -> list[SimulationResult]:
    """Run a quick scan with default variants only."""
    sim = DefenseSimulator()
    results: list[SimulationResult] = []
    for attack_type in ATTACK_REGISTRY:
        result = sim.run_simulation(attack_type, "default")
        results.append(result)
    ctx["_matrix"] = None
    return results


def _step_attack_matrix(ctx: dict[str, Any]) -> MatrixResult:
    """Run full attack matrix (if not already done)."""
    if "_matrix" in ctx and ctx["_matrix"] is not None:
        return ctx["_matrix"]
    sim = DefenseSimulator()
    matrix = sim.run_full_matrix()
    return matrix


def _step_generate_markdown_report(ctx: dict[str, Any]) -> str:
    """Generate a Markdown report from scan/matrix results."""
    results = ctx.get("scan") or ctx.get("attack_matrix", {})
    if isinstance(results, MatrixResult):
        results = results.results
    if not isinstance(results, list):
        results = []
    gen = SecurityReportGenerator(results=results)
    return gen.generate_markdown_report()


def _step_generate_json_report(ctx: dict[str, Any]) -> str:
    """Generate a JSON report from scan/matrix results."""
    results = ctx.get("scan") or ctx.get("attack_matrix", {})
    if isinstance(results, MatrixResult):
        results = results.results
    if not isinstance(results, list):
        results = []
    gen = SecurityReportGenerator(results=results)
    return gen.generate_json_report()


def _step_compliance_report(ctx: dict[str, Any]) -> str:
    """Generate a compliance-focused markdown report."""
    results = ctx.get("scan") or []
    if isinstance(results, MatrixResult):
        results = results.results
    gen = SecurityReportGenerator(
        results=results,
        title="MCP Compliance Assessment Report",
    )
    return gen.generate_markdown_report()


def _step_generate_keys(ctx: dict[str, Any]) -> dict[str, str]:
    """Generate a fresh Ed25519 key pair."""
    kp = generate_key_pair()
    ctx["_key_pair"] = kp
    return {"public_key": kp.public_key_hex, "algorithm": "Ed25519"}


def _step_sign_sample_tools(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Sign a set of sample tool descriptors."""
    from cryptomcp.signing.signer import SignedToolDescriptor

    kp = ctx.get("_key_pair")
    if kp is None:
        kp = generate_key_pair()
        ctx["_key_pair"] = kp

    signer = ToolSigner(kp, publisher_id="automation_engine")
    sample_tools = [
        {"name": "calculator", "description": "Arithmetic operations", "inputSchema": {}},
        {"name": "file_reader", "description": "Read workspace files", "inputSchema": {}},
        {"name": "database_query", "description": "Execute SQL queries", "inputSchema": {}},
    ]

    signed: list[dict[str, Any]] = []
    for tool in sample_tools:
        sd = signer.sign(tool)
        signed.append(sd.to_bundle())

    ctx["_signed_bundles"] = signed
    return signed


def _step_verify_signed_tools(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Verify all previously signed tool bundles."""
    from cryptomcp.signing.signer import SignedToolDescriptor

    bundles = ctx.get("_signed_bundles", [])
    verifier = ToolVerifier()
    results: list[dict[str, Any]] = []

    for bundle in bundles:
        sd = SignedToolDescriptor.from_bundle(bundle)
        vr = verifier.verify(sd)
        results.append({
            "tool_name": sd.tool.get("name", "unknown"),
            "valid": vr.valid,
            "hash_matches": vr.hash_matches,
            "signature_valid": vr.signature_valid,
            "error": vr.error,
        })

    return results


def _step_audit_log_check(ctx: dict[str, Any]) -> dict[str, Any]:
    """Create an audit log and verify its integrity."""
    log = MerkleAuditLog()

    bundles = ctx.get("_signed_bundles", [])
    for bundle in bundles:
        tool = bundle.get("tool", {})
        log.append(
            tool_name=tool.get("name", "unknown"),
            tool_hash=compute_tool_hash(tool),
            action="crypto_verify",
            decision="verified",
        )

    valid, error = log.verify_chain_integrity()
    return {
        "chain_length": log.chain_length,
        "integrity_valid": valid,
        "integrity_error": error,
    }
