"""MCPGuard command-line interface."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer

from mcpguard.benchmark import benchmark_server
from mcpguard.checker import check_protocol
from mcpguard.reporter import OutputFormat, render

app = typer.Typer(
    name="mcpguard",
    help="Security scanner, protocol validator, and benchmark suite for MCP servers.",
    no_args_is_help=True,
)


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(help="MCP server command to scan (e.g. 'python server.py')"),
    ],
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format: json, markdown"),
    ] = "json",
) -> None:
    """Scan an MCP server for protocol compliance and security issues."""
    fmt: OutputFormat
    if output == "json":
        fmt = "json"
    elif output == "markdown":
        fmt = "markdown"
    else:
        typer.echo(
            f"Error: unsupported output format {output!r}. Choose json or markdown.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        report = asyncio.run(check_protocol(target))
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(render(report, fmt=fmt))

    if not report.passed:
        raise typer.Exit(code=1)


@app.command("benchmark")
def benchmark_command(
    target: Annotated[str, typer.Argument(help="MCP server command to benchmark")],
    iterations: Annotated[int, typer.Option("--iterations", "-n", min=1)] = 5,
) -> None:
    """Benchmark MCP server startup and initialize latency."""
    try:
        report = asyncio.run(benchmark_server(target, iterations))
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        json.dumps(
            {
                "target": report.target,
                "iterations": report.iterations,
                "minimum_ms": round(report.minimum_ms, 3),
                "average_ms": round(report.average_ms, 3),
                "maximum_ms": round(report.maximum_ms, 3),
                "samples_ms": [round(value, 3) for value in report.samples_ms],
            },
            indent=2,
        )
    )


def main() -> None:
    """Entry point for the mcpguard CLI."""
    app()
