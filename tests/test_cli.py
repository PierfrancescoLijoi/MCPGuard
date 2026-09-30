"""Tests for the MCPGuard CLI."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from mcpguard.checker import CheckResult, ProtocolReport
from mcpguard.cli import app

runner = CliRunner()


def _passing_report() -> ProtocolReport:
    return ProtocolReport(
        target="python server.py",
        server_name="TestServer",
        server_version="1.0.0",
        protocol_version="2024-11-05",
        checks=[CheckResult(name="initialize_handshake", passed=True, message="ok")],
    )


def _failing_report() -> ProtocolReport:
    return ProtocolReport(
        target="python server.py",
        server_name=None,
        server_version=None,
        protocol_version=None,
        checks=[CheckResult(name="server_connection", passed=False, message="fail")],
    )


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


def test_scan_exit_0_on_pass() -> None:
    """scan exits with code 0 when all checks pass."""
    with patch("mcpguard.cli.check_protocol", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = _passing_report()
        result = runner.invoke(app, ["scan", "python server.py"])
    assert result.exit_code == 0


def test_scan_exit_1_on_fail() -> None:
    """scan exits with code 1 when any check fails."""
    with patch("mcpguard.cli.check_protocol", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = _failing_report()
        result = runner.invoke(app, ["scan", "python server.py"])
    assert result.exit_code == 1


def test_scan_json_output_by_default() -> None:
    """scan emits valid JSON by default."""
    with patch("mcpguard.cli.check_protocol", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = _passing_report()
        result = runner.invoke(app, ["scan", "python server.py"])
    data = json.loads(result.output)
    assert data["passed"] is True


def test_scan_markdown_output() -> None:
    """scan emits Markdown when --output markdown is passed."""
    with patch("mcpguard.cli.check_protocol", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = _passing_report()
        result = runner.invoke(
            app, ["scan", "python server.py", "--output", "markdown"]
        )
    assert result.exit_code == 0
    assert "PASSED" in result.output


def test_scan_invalid_output_format() -> None:
    """scan exits with code 2 for unsupported --output values."""
    result = runner.invoke(app, ["scan", "python server.py", "--output", "xml"])
    assert result.exit_code == 2


def test_scan_passes_fuzz_options_to_checker() -> None:
    with patch("mcpguard.cli.check_protocol", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = _passing_report()
        result = runner.invoke(
            app,
            ["scan", "https://example.test/mcp", "--fuzz", "--fuzz-max-calls", "7"],
        )
    assert result.exit_code == 0
    mock_check.assert_awaited_once_with(
        "https://example.test/mcp",
        fuzz=True,
        fuzz_max_calls=7,
        allow_dangerous_tools=False,
        headers=None,
        expected_tool_fingerprint=None,
    )
