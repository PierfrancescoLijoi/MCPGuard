"""Tests for the report formatters."""

from __future__ import annotations

import json

import pytest

from mcpguard.checker import CheckResult, ProtocolReport
from mcpguard.reporter import render, render_json, render_markdown


def _make_report(*, passed: bool = True) -> ProtocolReport:
    return ProtocolReport(
        target="python server.py",
        server_name="TestServer",
        server_version="1.2.3",
        protocol_version="2024-11-05",
        checks=[
            CheckResult(
                name="initialize_handshake",
                passed=passed,
                message="ok" if passed else "fail",
            ),
        ],
    )


def test_render_json_is_valid_json() -> None:
    """render_json output is valid JSON."""
    data = json.loads(render_json(_make_report()))
    assert data["passed"] is True
    assert data["target"] == "python server.py"
    assert isinstance(data["checks"], list)


def test_render_json_failed_report() -> None:
    """render_json reflects a failed report."""
    data = json.loads(render_json(_make_report(passed=False)))
    assert data["passed"] is False


def test_render_json_server_block() -> None:
    """render_json includes server name and version."""
    data = json.loads(render_json(_make_report()))
    assert data["server"]["name"] == "TestServer"
    assert data["server"]["version"] == "1.2.3"


def test_render_markdown_passed_header() -> None:
    """render_markdown includes PASSED in the header for a passing report."""
    assert "PASSED" in render_markdown(_make_report(passed=True))


def test_render_markdown_failed_header() -> None:
    """render_markdown includes FAILED in the header for a failing report."""
    assert "FAILED" in render_markdown(_make_report(passed=False))


def test_render_dispatches_json() -> None:
    """render('json') produces parseable JSON."""
    json.loads(render(_make_report(), fmt="json"))


def test_render_dispatches_markdown() -> None:
    """render('markdown') produces a Markdown string."""
    output = render(_make_report(), fmt="markdown")
    assert "#" in output


def test_render_invalid_format_raises() -> None:
    """render raises ValueError for unknown format strings."""
    with pytest.raises(ValueError, match="unsupported output format"):
        render(_make_report(), fmt="xml")  # type: ignore[arg-type]
