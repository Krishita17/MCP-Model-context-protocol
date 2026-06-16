"""CLI entry point for MCPShield defense framework."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from mcpshield.static_analysis.scanner import StaticScanner
from mcpshield.proxy.interceptor import MCPShieldProxy

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """MCPShield — MCP Defense Framework."""


@main.command()
@click.option("--tool-file", required=True, type=click.Path(exists=True), help="Tool JSON file")
def scan(tool_file: str) -> None:
    """Scan a tool description for threats (Layer 1)."""
    tool = json.loads(Path(tool_file).read_text())
    scanner = StaticScanner()
    result = scanner.scan(tool)

    table = Table(title=f"Scan Results: {result.tool_name}")
    table.add_column("Finding", style="cyan")
    table.add_column("Level", style="red")
    table.add_column("Description")

    for f in result.findings:
        table.add_row(f.finding_type.value, f.threat_level.value, f.description)

    console.print(table)
    console.print(f"\nThreat Level: [bold]{result.threat_level.value}[/bold]")
    console.print(f"Risk Score: {result.score:.2f}")


@main.command()
@click.option("--tool-file", required=True, type=click.Path(exists=True))
@click.option("--bundle-file", type=click.Path(exists=True), help="Signed bundle (optional)")
def register(tool_file: str, bundle_file: str | None) -> None:
    """Register a tool through the full MCPShield pipeline."""
    tool = json.loads(Path(tool_file).read_text())
    bundle = json.loads(Path(bundle_file).read_text()) if bundle_file else None

    proxy = MCPShieldProxy()
    result = proxy.register_tool(tool, signed_bundle=bundle)

    console.print(f"\nDecision: [bold]{result.decision}[/bold]")
    console.print(f"Tool: {result.tool_name}")
    for layer, details in result.layer_results.items():
        console.print(f"  {layer}: {json.dumps(details, indent=2)}")


if __name__ == "__main__":
    main()
