"""Tests for the MCPGuard CLI."""

from typer.testing import CliRunner

from mcpguard.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    """Invoking the CLI with no args shows the help message."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "mcpguard" in result.output


def test_scan_help() -> None:
    """The scan subcommand exposes a --help flag."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "target" in result.output.lower()


def test_scan_runs() -> None:
    """The scan command accepts a target argument and exits cleanly."""
    result = runner.invoke(app, ["scan", "python server.py"])
    assert result.exit_code == 0
    assert "Scanning" in result.output