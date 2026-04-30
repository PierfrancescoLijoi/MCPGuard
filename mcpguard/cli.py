"""MCPGuard command-line interface."""

from __future__ import annotations

import typer

app = typer.Typer(
    name="mcpguard",
    help="Security scanner, protocol validator, and benchmark suite for MCP servers.",
    no_args_is_help=True,
)


@app.command()
def scan(
    target: str = typer.Argument(..., help="MCP server command to scan (e.g. 'python server.py')"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json, markdown"),
) -> None:
    """Scan an MCP server for protocol compliance and security issues."""
    typer.echo(f"Scanning: {target}")
    typer.echo(f"Output format: {output}")


def main() -> None:
    """Entry point for the mcpguard CLI."""
    app()