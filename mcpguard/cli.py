"""MCPGuard command-line interface."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Annotated, cast

import typer

from mcpguard.baseline import compare_performance
from mcpguard.benchmark import benchmark_server, benchmark_throughput
from mcpguard.checker import check_protocol
from mcpguard.http_transport import ModernHttpClient
from mcpguard.reporter import OutputFormat, render

app = typer.Typer(
    name="mcpguard",
    help="Security scanner, protocol validator, and benchmark suite for MCP servers.",
    no_args_is_help=True,
)


def _emit(text: str) -> None:
    """Print a report, falling back to UTF-8 bytes on a legacy console encoding."""
    try:
        typer.echo(text)
    except UnicodeEncodeError:
        sys.stdout.flush()
        sys.stdout.buffer.write((text + "\n").encode("utf-8"))
        sys.stdout.flush()


def _auth_headers(values: list[str], bearer_token_env: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        name, separator, header_value = value.partition(":")
        if not separator or not name.strip() or not header_value.strip():
            raise ValueError("headers must use 'Name: value' format")
        headers[name.strip()] = header_value.strip()
    if bearer_token_env:
        token = os.environ.get(bearer_token_env)
        if not token:
            raise ValueError(f"environment variable {bearer_token_env!r} is not set")
        headers["Authorization"] = f"Bearer {token}"
    return headers


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(help="MCP server command to scan (e.g. 'python server.py')"),
    ],
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format: json, markdown, sarif"),
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
    header: Annotated[
        list[str] | None, typer.Option("--header", help="HTTP header as 'Name: value'")
    ] = None,
    bearer_token_env: Annotated[
        str | None,
        typer.Option(help="Environment variable containing a bearer token"),
    ] = None,
    tool_baseline: Annotated[
        Path | None, typer.Option(help="Trusted tool fingerprint JSON file")
    ] = None,
    write_tool_baseline: Annotated[
        Path | None, typer.Option(help="Write the observed tool fingerprint")
    ] = None,
) -> None:
    """Scan an MCP server for protocol compliance and security issues."""
    fmt: OutputFormat
    if output == "json":
        fmt = "json"
    elif output == "markdown":
        fmt = "markdown"
    elif output == "sarif":
        fmt = "sarif"
    else:
        typer.echo(
            f"Error: unsupported output format {output!r}. "
            "Choose json, markdown or sarif.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        headers = _auth_headers(header or [], bearer_token_env)
        expected_fingerprint = None
        if tool_baseline:
            expected_fingerprint = str(
                json.loads(tool_baseline.read_text(encoding="utf-8"))["fingerprint"]
            )
        report = asyncio.run(
            check_protocol(
                target,
                fuzz=fuzz,
                fuzz_max_calls=fuzz_max_calls,
                allow_dangerous_tools=allow_dangerous_tools,
                headers=headers or None,
                expected_tool_fingerprint=expected_fingerprint,
            )
        )
        if write_tool_baseline:
            if report.tool_fingerprint is None:
                raise ValueError("target did not advertise tools")
            write_tool_baseline.write_text(
                json.dumps({"fingerprint": report.tool_fingerprint}, indent=2) + "\n",
                encoding="utf-8",
            )
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    _emit(render(report, fmt=fmt))

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
    baseline: Annotated[
        Path | None, typer.Option(help="Performance baseline JSON")
    ] = None,
    save_baseline: Annotated[
        Path | None, typer.Option(help="Write current metrics")
    ] = None,
    max_regression_percent: Annotated[float, typer.Option(min=0)] = 10.0,
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
        result = asyncio.run(run())
        if baseline:
            previous = json.loads(baseline.read_text(encoding="utf-8"))
            comparison = compare_performance(
                cast(float, result["p95_ms"]),
                float(previous["p95_ms"]),
                max_regression_percent=max_regression_percent,
            )
            result["baseline"] = {
                "passed": comparison.passed,
                "regression_percent": round(comparison.regression_percent, 3),
            }
        if save_baseline:
            save_baseline.write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
        typer.echo(json.dumps(result, indent=2))
        if baseline and not result["baseline"]["passed"]:  # type: ignore[index]
            raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def main() -> None:
    """Entry point for the mcpguard CLI."""
    app()
