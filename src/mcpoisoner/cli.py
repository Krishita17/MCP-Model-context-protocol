"""CLI entry point for MCPoisoner red-team toolkit."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from mcpoisoner.attacks.base import AttackClass, AttackConfig
from mcpoisoner.attacks import ATTACK_REGISTRY
from mcpoisoner.harness.runner import AttackMatrixRunner, MatrixConfig

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
def attack(attack: str, llm: str, framework: str, variant: str, iterations: int) -> None:
    """Run a single attack against a specific configuration."""
    config = AttackConfig(
        attack_class=AttackClass(attack),
        llm_backend=llm,
        agent_framework=framework,
        payload_variant=variant,
        iterations=iterations,
    )

    attack_cls = ATTACK_REGISTRY[attack]
    instance = attack_cls(config)

    console.print(f"\n[bold red]MCPoisoner[/bold red] — Executing {attack}")
    console.print(f"  Target: {llm} / {framework} / variant={variant}")
    console.print(f"  Iterations: {iterations}\n")

    results = asyncio.run(instance.run())

    table = Table(title="Attack Results")
    table.add_column("Iteration", style="cyan")
    table.add_column("Success", style="red")
    table.add_column("ASR", style="yellow")
    table.add_column("Exfil (bytes)", style="magenta")
    table.add_column("Regulatory Triggers", style="green")

    for i, r in enumerate(results, 1):
        table.add_row(
            str(i),
            "YES" if r.success else "NO",
            f"{r.attack_success_rate:.2%}",
            str(r.data_exfiltration_bytes),
            str(len(r.regulatory_triggers)),
        )

    console.print(table)


@main.command()
@click.option("--output", type=click.Path(), default="results", help="Output directory")
@click.option("--parallel", type=int, default=4, help="Parallel configurations")
@click.option("--iterations", type=int, default=10, help="Iterations per configuration")
def matrix(output: str, parallel: int, iterations: int) -> None:
    """Run the full 60-configuration attack matrix."""
    config = MatrixConfig(
        iterations_per_config=iterations,
        output_dir=Path(output),
        parallel_configs=parallel,
    )

    runner = AttackMatrixRunner(config)
    console.print("\n[bold red]MCPoisoner[/bold red] — Full Attack Matrix")
    console.print(f"  Configurations: {len(runner.generate_configs())}")
    console.print(f"  Iterations per config: {iterations}\n")

    result = asyncio.run(runner.run_matrix())

    table = Table(title="Attack Matrix Summary")
    table.add_column("Attack Class", style="cyan")
    table.add_column("Total Runs", style="white")
    table.add_column("Successful", style="red")
    table.add_column("ASR", style="yellow")

    for ac, stats in result.summary()["by_attack_class"].items():
        table.add_row(ac, str(stats["total"]), str(stats["successful"]), f"{stats['asr']:.2%}")

    console.print(table)
    asyncio.run(runner.save_results(result, Path(output)))
    console.print(f"\n[green]Results saved to {output}/[/green]")


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


if __name__ == "__main__":
    main()
