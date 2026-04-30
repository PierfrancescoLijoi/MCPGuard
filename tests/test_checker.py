"""Tests for the protocol checker module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpguard.checker import CheckResult, ProtocolReport, check_protocol


def test_protocol_report_passed_all_ok() -> None:
    """ProtocolReport.passed is True when all checks passed."""
    report = ProtocolReport(
        target="python server.py",
        server_name="test",
        server_version="1.0",
        protocol_version="2024-11-05",
        checks=[
            CheckResult(name="a", passed=True, message="ok"),
            CheckResult(name="b", passed=True, message="ok"),
        ],
    )
    assert report.passed is True


def test_protocol_report_passed_one_failed() -> None:
    """ProtocolReport.passed is False when any check failed."""
    report = ProtocolReport(
        target="python server.py",
        server_name=None,
        server_version=None,
        protocol_version=None,
        checks=[
            CheckResult(name="a", passed=True, message="ok"),
            CheckResult(name="b", passed=False, message="fail"),
        ],
    )
    assert report.passed is False


def test_protocol_report_passed_no_checks() -> None:
    """ProtocolReport.passed is False when there are no checks."""
    report = ProtocolReport(
        target="python server.py",
        server_name=None,
        server_version=None,
        protocol_version=None,
    )
    assert report.passed is False


async def test_check_protocol_empty_target_raises() -> None:
    """check_protocol raises ValueError for an empty target."""
    with pytest.raises(ValueError, match="must not be empty"):
        await check_protocol("")


async def test_check_protocol_connection_failure() -> None:
    """check_protocol returns a failed report when the server cannot be reached."""
    mock_cm: MagicMock = MagicMock()
    mock_cm.__aenter__ = AsyncMock(side_effect=OSError("no such file"))

    with patch("mcpguard.checker.stdio_client", return_value=mock_cm):
        report = await check_protocol("nonexistent-server-binary")

    assert report.passed is False
    assert any(c.name == "server_connection" for c in report.checks)
    assert not report.checks[0].passed