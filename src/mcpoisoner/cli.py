"""CLI entry point for MCPoisoner red-team toolkit."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from mcpoisoner.attacks.base import AttackClass, AttackConfig
from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpoisoner.backends import available_backends, is_backend_available
from mcpoisoner.harness.runner import AGENT_FRAMEWORKS, AttackMatrixRunner, MatrixConfig
from mcpoisoner.results.writer import write_run_result, write_aggregate_csv

load_dotenv()

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """MCPoisoner — MCP Attack Simulation Toolkit for Security Research."""


@main.command()
@click.option("--attack", type=click.Choice([a.value for a in AttackClass]), required=True)
@click.option("--llm", type=str, default="gpt-4o", help="LLM backend to target")
@click.option("--framework", type=str, default="langchain", help="Agent framework to target")
@click.option("--variant", type=str, default="default", help="Payload variant")
@click.option("--iterations", type=int, default=10, help="Number of iterations")
@click.option("--output", type=click.Path(), default="results", help="Output directory")
@click.option(
    "--temperature",
    type=float,
    default=0.0,
    help="LLM sampling temperature. 0=deterministic (identical every run); use 0.7 for run-to-run variation.",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Crash loudly with full traceback on any failed LLM call (no silent fallback).",
)
@click.option(
    "--show-output/--no-show-output",
    default=True,
    help="Print each iteration's raw LLM output and tool calls (default: on).",
)
def attack(
    attack: str,
    llm: str,
    framework: str,
    variant: str,
    iterations: int,
    output: str,
    temperature: float,
    strict: bool,
    show_output: bool,
) -> None:
    """Run a single attack against a specific configuration."""
    if strict:
        os.environ["MCPOISONER_STRICT"] = "1"
    if not is_backend_available(llm):
        console.print(f"\n[bold red]Error:[/bold red] Backend '{llm}' not available.")
        avail = available_backends()
        if avail:
            console.print(f"  Available backends: {', '.join(avail)}")
        else:
            console.print("  No backends configured. Set API keys in .env file.")
        return

    config = AttackConfig(
        attack_class=AttackClass(attack),
        llm_backend=llm,
        agent_framework=framework,
        payload_variant=variant,
        iterations=iterations,
        temperature=temperature,
    )

    attack_cls = ATTACK_REGISTRY[attack]
    instance = attack_cls(config)

    console.print(f"\n[bold red]MCPoisoner[/bold red] — Executing {attack}")
    console.print(f"  Target: {llm} / {framework} / variant={variant}")
    console.print(f"  Iterations: {iterations}  |  Temperature: {temperature}")
    console.print(f"  Mode: [bold green]REAL LLM API CALLS[/bold green]\n")

    results = asyncio.run(instance.run())

    table = Table(title="Attack Results")
    table.add_column("Iter", style="cyan")
    table.add_column("Success", style="red")
    table.add_column("MCPShield", style="blue")
    table.add_column("Exfil (bytes)", style="magenta")
    table.add_column("Tools called", style="white")
    table.add_column("Error", style="dim")

    output_dir = Path(output)
    for i, r in enumerate(results, 1):
        r.iteration = i
        try:
            write_run_result(r, output_dir, iteration=i)
        except Exception:
            pass

        shield_blocked = r.details.get("mcpshield_blocked", False)
        if r.success is None:
            success_cell = "[yellow]UNKNOWN (error)[/yellow]"
        elif r.success:
            success_cell = "[bold red]YES[/bold red]"
        else:
            success_cell = "NO"
        tools_called = [c.get("name") for c in r.details.get("tool_calls", [])]
        table.add_row(
            str(i),
            success_cell,
            "[blue]BLOCKED[/blue]" if shield_blocked else "passed",
            str(r.data_exfiltration_bytes),
            ", ".join(tools_called) if tools_called else "—",
            (r.error or "")[:40],
        )

        # Check 3: make the real LLM output visible per iteration.
        if show_output and not shield_blocked:
            raw = (r.llm_raw_output or "").strip()
            console.print(
                f"  [dim]iter {i}[/dim] "
                f"[bold]tools:[/bold] {tools_called or '—'}  "
                f"[bold]LLM:[/bold] {raw[:200] or '[no output]'}"
            )

    console.print(table)

    # Aggregate
    try:
        csv_path = write_aggregate_csv(results, output_dir)
        console.print(f"\n[green]Results saved to {output_dir}/[/green]")
        console.print(f"  CSV: {csv_path}")
    except Exception:
        pass

    # Summary — ASR is over VALID runs only (errored runs are unknown, excluded)
    successes = sum(1 for r in results if r.success is True)
    valid = sum(1 for r in results if r.success is not None)
    errors = sum(1 for r in results if r.error)
    asr = successes / valid if valid else 0.0
    console.print(
        f"\n  ASR (valid runs): [bold]{successes}/{valid} = {asr:.0%}[/bold]"
        + (f"  |  [yellow]{errors} errored (excluded)[/yellow]" if errors else "")
    )
    if any(r.llm_raw_output for r in results):
        console.print("  [green]✓ Real LLM responses captured[/green]")
    if valid and successes == valid and valid > 1:
        console.print(
            "  [yellow]Note: 100% ASR across all valid runs. With temperature=0 this is "
            "expected (deterministic). Use --temperature 0.7 for run-to-run variation.[/yellow]"
        )


@main.command()
@click.option("--output", type=click.Path(), default="results", help="Output directory")
@click.option("--parallel", type=int, default=4, help="Parallel configurations")
@click.option("--iterations", type=int, default=10, help="Iterations per configuration")
@click.option(
    "--framework",
    type=click.Choice(["langchain", "crewai", "autogen"]),
    multiple=True,
    help="Limit to specific agent framework(s). Repeatable. Default: all three.",
)
@click.option(
    "--temperature",
    type=float,
    default=0.0,
    help="LLM sampling temperature. 0=deterministic; use 0.7 for run-to-run variation.",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Crash loudly with full traceback on any failed LLM call (no silent fallback).",
)
def matrix(
    output: str,
    parallel: int,
    iterations: int,
    framework: tuple[str, ...],
    temperature: float,
    strict: bool,
) -> None:
    """Run the full attack matrix (optionally limited to specific frameworks)."""
    if strict:
        os.environ["MCPOISONER_STRICT"] = "1"
    avail = available_backends()
    console.print("\n[bold red]MCPoisoner[/bold red] — Full Attack Matrix")
    console.print(f"  Mode: [bold green]REAL LLM API CALLS[/bold green]")
    console.print(f"  Available backends: {', '.join(avail) if avail else '[red]NONE[/red]'}")

    if not avail:
        console.print("\n[bold red]Error:[/bold red] No backends available. Set API keys in .env file.")
        return

    frameworks = list(framework) if framework else list(AGENT_FRAMEWORKS)
    console.print(f"  Frameworks: {', '.join(frameworks)}  |  Temperature: {temperature}")

    config = MatrixConfig(
        agent_frameworks=frameworks,
        iterations_per_config=iterations,
        temperature=temperature,
        output_dir=Path(output),
        parallel_configs=parallel,
    )

    runner = AttackMatrixRunner(config)
    total_configs = len(runner.generate_configs())
    console.print(f"  Configurations: {total_configs}")
    console.print(f"  Iterations per config: {iterations}\n")

    result = asyncio.run(runner.run_matrix())

    # Attack class breakdown
    table = Table(title="Attack Matrix — By Attack Class")
    table.add_column("Attack Class", style="cyan")
    table.add_column("Total Runs", style="white")
    table.add_column("Successful", style="red")
    table.add_column("ASR", style="yellow")

    for ac, stats in result.summary()["by_attack_class"].items():
        table.add_row(ac, str(stats["total"]), str(stats["successful"]), f"{stats['asr']:.2%}")
    console.print(table)

    # LLM backend breakdown
    table2 = Table(title="Attack Matrix — By LLM Backend")
    table2.add_column("Backend", style="cyan")
    table2.add_column("Total Runs", style="white")
    table2.add_column("Successful", style="red")
    table2.add_column("ASR", style="yellow")

    for llm, stats in result.summary()["by_llm_backend"].items():
        table2.add_row(llm, str(stats["total"]), str(stats["successful"]), f"{stats['asr']:.2%}")
    console.print(table2)

    asyncio.run(runner.save_results(result, Path(output)))

    # Summary
    console.print(f"\n[green]Results saved to {output}/[/green]")
    console.print(f"  Completed: {result.completed_configs}/{result.total_configs} configs")
    console.print(f"  Total attacks: {result.total_attacks}")
    console.print(f"  Overall ASR: [bold]{result.overall_asr:.2%}[/bold]")
    if result.skipped_backends:
        console.print(f"  [yellow]Skipped backends (no API key): {', '.join(result.skipped_backends)}[/yellow]")
    if result.error_count:
        console.print(f"  [yellow]Errors: {result.error_count}[/yellow]")


@main.command()
def list_attacks() -> None:
    """List all available attack classes and their variants."""
    table = Table(title="Available Attack Classes")
    table.add_column("Class", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("MITRE ID", style="yellow")
    table.add_column("Crypto Blocked", style="green")

    for name, cls in ATTACK_REGISTRY.items():
        crypto = "Full" if "Fully" in cls.crypto_exploitability else "Partial"
        table.add_row(name, cls.severity.value, cls.mitre_atlas_id, crypto)

    console.print(table)


@main.command()
def backends() -> None:
    """Show available LLM backends and their configuration status."""
    from mcpoisoner.backends import BACKEND_MAP

    table = Table(title="LLM Backend Status")
    table.add_column("Backend", style="cyan")
    table.add_column("Provider", style="white")
    table.add_column("Model", style="white")
    table.add_column("Status", style="green")

    for name, cfg in BACKEND_MAP.items():
        available = is_backend_available(name)
        status = "[bold green]✓ Ready[/bold green]" if available else "[red]✗ Missing key[/red]"
        table.add_row(name, cfg["provider"], cfg["model"], status)

    console.print(table)


if __name__ == "__main__":
    main()
