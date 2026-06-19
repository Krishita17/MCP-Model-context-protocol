"""Result persistence — per-run JSON and aggregate CSV."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcpoisoner.attacks.base import AttackResult


def write_run_result(result: AttackResult, output_dir: Path, iteration: int = 0) -> Path:
    runs_dir = output_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    filename = (
        f"run_{ts}_{result.attack_class.value}"
        f"_{result.llm_backend}_{result.agent_framework}.json"
    )
    filepath = runs_dir / filename

    data = {
        "attack_class": result.attack_class.value,
        "variant": result.details.get("variant", "default"),
        "llm_backend": result.llm_backend,
        "agent_framework": result.agent_framework,
        "iteration": iteration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_success": result.success,
        "mcpshield_blocked": result.details.get("mcpshield_blocked", False),
        "mcpshield_layer_triggered": result.details.get("mcpshield_layer_triggered"),
        "time_to_detection_ms": result.time_to_detection_ms,
        "data_exfiltrated_bytes": result.data_exfiltration_bytes,
        "regulatory_trigger": bool(result.regulatory_triggers),
        "crypto_defense_effective": result.crypto_defense_effective,
        "llm_raw_output": result.llm_raw_output,
        "error": result.error,
    }

    filepath.write_text(json.dumps(data, indent=2, default=str))
    return filepath


def write_aggregate_csv(all_results: list[AttackResult], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "matrix_results.csv"

    grouped: dict[tuple[str, str, str], list[AttackResult]] = defaultdict(list)
    for r in all_results:
        key = (r.attack_class.value, r.llm_backend, r.agent_framework)
        grouped[key].append(r)

    rows: list[dict[str, Any]] = []
    for (attack, llm, framework), results in sorted(grouped.items()):
        n = len(results)
        # Valid runs = those that actually produced an outcome (reached the LLM
        # or were blocked pre-LLM). Errored runs have success=None and are
        # EXCLUDED from the ASR denominator so a failed API call is never
        # silently counted as a resisted attack.
        valid = [r for r in results if r.success is not None]
        successes = sum(1 for r in results if r.success is True)
        blocked = sum(1 for r in results if r.details.get("mcpshield_blocked"))
        ttds = [r.time_to_detection_ms for r in results if r.time_to_detection_ms is not None]
        exfil = sum(r.data_exfiltration_bytes for r in results)
        reg_triggers = sum(1 for r in results if r.regulatory_triggers)
        crypto_eff = sum(1 for r in results if r.crypto_defense_effective)
        errors = sum(1 for r in results if r.error)

        rows.append({
            "attack_class": attack,
            "llm_backend": llm,
            "agent_framework": framework,
            "total_runs": n,
            "valid_runs": len(valid),
            "successful_attacks": successes,
            "mean_asr": round(successes / len(valid), 4) if valid else "",
            "mcpshield_blocked": blocked,
            "mean_ttd_ms": round(sum(ttds) / max(len(ttds), 1), 2) if ttds else "",
            "total_exfil_bytes": exfil,
            "regulatory_triggers": reg_triggers,
            "crypto_defense_effective": crypto_eff,
            "errors": errors,
        })

    if rows:
        fieldnames = list(rows[0].keys())
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    return filepath
