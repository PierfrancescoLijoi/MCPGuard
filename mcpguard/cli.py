"""MCPGuard command-line interface."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer

from mcpguard.benchmark import benchmark_server, benchmark_throughput
from mcpguard.checker import check_protocol
from mcpguard.http_transport import ModernHttpClient
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
    fuzz: Annotated[
        bool,
        typer.Option("--fuzz", help="Execute bounded schema-derived tool cases"),
    ] = False,
    fuzz_max_calls: Annotated[
        int,
        typer.Option("--fuzz-max-calls", min=1, max=1000),
    ] = 25,
    allow_dangerous_tools: Annotated[
        bool,
        typer.Option(
            "--allow-dangerous-tools",
            help="Allow fuzzing tools that appear destructive or execute commands",
        ),
    ] = False,
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
        report = asyncio.run(
            check_protocol(
                target,
                fuzz=fuzz,
                fuzz_max_calls=fuzz_max_calls,
                allow_dangerous_tools=allow_dangerous_tools,
            )
        )
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


@app.command("load-test")
def load_test_command(
    target: Annotated[str, typer.Argument(help="Streamable HTTP MCP endpoint")],
    requests: Annotated[int, typer.Option("--requests", "-n", min=1)] = 100,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c", min=1)] = 10,
) -> None:
    """Measure concurrent server/discover throughput and latency."""
    if not target.startswith(("http://", "https://")):
        typer.echo("Error: load-test requires an HTTP URL", err=True)
        raise typer.Exit(code=2)
    if concurrency > requests:
        typer.echo("Error: concurrency cannot exceed requests", err=True)
        raise typer.Exit(code=2)

    client = ModernHttpClient(target)

    async def run() -> dict[str, object]:
        try:

            async def operation() -> None:
                await client.discover()

            report = await benchmark_throughput(
                operation, requests=requests, concurrency=concurrency
            )
            return {
                "target": target,
                "requests": report.requests,
                "completed": report.completed,
                "errors": report.errors,
                "duration_seconds": round(report.duration_seconds, 3),
                "requests_per_second": round(report.requests_per_second, 3),
                "p50_ms": round(report.p50_ms, 3),
                "p95_ms": round(report.p95_ms, 3),
            }
        finally:
            await client.aclose()

    try:
        typer.echo(json.dumps(asyncio.run(run()), indent=2))
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def main() -> None:
    """Entry point for the mcpguard CLI."""
    app()
