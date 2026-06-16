"""CLI entry point for CryptoMCP operations."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from cryptomcp.signing.keys import generate_key_pair, save_key_pair, load_key_pair
from cryptomcp.signing.signer import ToolSigner, ToolVerifier, SignedToolDescriptor

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """CryptoMCP — Cryptographic Integrity for MCP Tool Descriptions."""


@main.command()
@click.option("--publisher-id", required=True, help="Publisher identifier")
@click.option("--output-dir", type=click.Path(), default="keys", help="Key output directory")
def keygen(publisher_id: str, output_dir: str) -> None:
    """Generate a new Ed25519 key pair for a publisher."""
    key_pair = generate_key_pair()
    out = Path(output_dir)
    save_key_pair(key_pair, out, publisher_id)
    console.print(f"[green]Key pair generated for '{publisher_id}'[/green]")
    console.print(f"  Public key:  {key_pair.public_key_hex[:32]}...")
    console.print(f"  Saved to:    {out}/")


@main.command()
@click.option("--tool-file", required=True, type=click.Path(exists=True), help="Tool JSON file")
@click.option("--publisher-id", required=True, help="Publisher identifier")
@click.option("--key-dir", type=click.Path(exists=True), default="keys", help="Key directory")
@click.option("--output", type=click.Path(), help="Output bundle file")
@click.option("--version", default="1.0.0", help="Tool version")
def sign(tool_file: str, publisher_id: str, key_dir: str, output: str | None, version: str) -> None:
    """Sign a tool description with Ed25519."""
    key_pair = load_key_pair(Path(key_dir), publisher_id)
    tool = json.loads(Path(tool_file).read_text())

    signer = ToolSigner(key_pair, publisher_id)
    signed = signer.sign(tool, version=version)

    bundle = signed.to_bundle()
    out_path = Path(output) if output else Path(tool_file).with_suffix(".signed.json")
    out_path.write_text(json.dumps(bundle, indent=2))

    console.print(f"[green]Tool signed successfully[/green]")
    console.print(f"  Hash:      {signed.tool_hash[:32]}...")
    console.print(f"  Signature: {signed.signature[:32]}...")
    console.print(f"  Bundle:    {out_path}")


@main.command()
@click.option("--bundle-file", required=True, type=click.Path(exists=True), help="Signed bundle")
@click.option("--baseline-file", type=click.Path(exists=True), help="Approved baselines JSON")
def verify(bundle_file: str, baseline_file: str | None) -> None:
    """Verify a signed tool description bundle."""
    bundle = json.loads(Path(bundle_file).read_text())
    descriptor = SignedToolDescriptor.from_bundle(bundle)

    baselines = {}
    if baseline_file:
        baselines = json.loads(Path(baseline_file).read_text())

    verifier = ToolVerifier(approved_baselines=baselines)
    result = verifier.verify(descriptor)

    table = Table(title="Verification Result")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green" if result.valid else "red")

    table.add_row("Hash Match", "PASS" if result.hash_matches else "FAIL")
    table.add_row("Signature Valid", "PASS" if result.signature_valid else "FAIL")
    table.add_row("Publisher Auth", "PASS" if result.publisher_authenticated else "FAIL")
    if result.baseline_matches is not None:
        table.add_row("Baseline Match", "PASS" if result.baseline_matches else "FAIL")
    table.add_row("Overall", "[bold green]VALID[/bold green]" if result.valid else f"[bold red]INVALID: {result.error}[/bold red]")

    console.print(table)


if __name__ == "__main__":
    main()
