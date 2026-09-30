"""Tests for the protocol checker module."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.types import (
    Implementation,
    InitializeResult,
    ServerCapabilities,
    ToolsCapability,
)

from mcpguard.checker import (
    KNOWN_PROTOCOL_VERSIONS,
    CheckResult,
    ProtocolReport,
    check_http_protocol,
    check_protocol,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_init_result(
    *,
    protocol_version: str = "2024-11-05",
    server_name: str = "TestServer",
    server_version: str = "1.0.0",
    with_tools: bool = False,
) -> InitializeResult:
    caps = ServerCapabilities(
        tools=ToolsCapability() if with_tools else None,
    )
    return InitializeResult(
        protocolVersion=protocol_version,
        serverInfo=Implementation(name=server_name, version=server_version),
        capabilities=caps,
    )


@contextmanager
def _mock_server(
    init_result: InitializeResult,
) -> Generator[MagicMock, None, None]:
    """Patch stdio_client and ClientSession so no real process is spawned."""
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.initialize = AsyncMock(return_value=init_result)
    session.list_tools = AsyncMock(return_value=MagicMock(tools=[]))
    session.list_resources = AsyncMock(return_value=MagicMock(resources=[]))
    session.list_prompts = AsyncMock(return_value=MagicMock(prompts=[]))

    stdio_cm = MagicMock()
    stdio_cm.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock()))
    stdio_cm.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("mcpguard.checker.stdio_client", return_value=stdio_cm),
        patch("mcpguard.checker.ClientSession", return_value=session),
    ):
        yield session


# ---------------------------------------------------------------------------
# ProtocolReport unit tests
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# KNOWN_PROTOCOL_VERSIONS
# ---------------------------------------------------------------------------


def test_known_protocol_versions_contains_stable() -> None:
    """The constant includes the stable protocol versions from the MCP spec."""
    assert "2024-11-05" in KNOWN_PROTOCOL_VERSIONS
    assert "2025-03-26" in KNOWN_PROTOCOL_VERSIONS
    assert "2025-06-18" in KNOWN_PROTOCOL_VERSIONS
    assert "2025-11-25" in KNOWN_PROTOCOL_VERSIONS


# ---------------------------------------------------------------------------
# check_protocol — input validation
# ---------------------------------------------------------------------------


async def test_check_protocol_empty_target_raises() -> None:
    """check_protocol raises ValueError for an empty target."""
    with pytest.raises(ValueError, match="must not be empty"):
        await check_protocol("")


# ---------------------------------------------------------------------------
# check_protocol — mocked server scenarios
# ---------------------------------------------------------------------------


async def test_check_protocol_passing_server() -> None:
    """check_protocol passes all checks for a well-behaved server."""
    with _mock_server(_make_init_result()):
        report = await check_protocol("python server.py")

    assert report.passed is True
    assert report.protocol_version == "2024-11-05"
    assert report.server_name == "TestServer"


async def test_check_protocol_unknown_version() -> None:
    """check_protocol flags an unknown protocol version."""
    with _mock_server(_make_init_result(protocol_version="1999-01-01")):
        report = await check_protocol("python server.py")

    version_check = next(c for c in report.checks if c.name == "protocol_version_known")
    assert version_check.passed is False
    assert report.passed is False


async def test_check_protocol_empty_server_name() -> None:
    """check_protocol flags an empty serverInfo.name."""
    with _mock_server(_make_init_result(server_name="")):
        report = await check_protocol("python server.py")

    name_check = next(c for c in report.checks if c.name == "server_name_nonempty")
    assert name_check.passed is False
    assert report.passed is False


async def test_check_protocol_tools_capability_runs_list() -> None:
    """check_protocol calls tools/list when the tools capability is declared."""
    with _mock_server(_make_init_result(with_tools=True)) as session:
        report = await check_protocol("python server.py")

    session.list_tools.assert_called_once()
    tools_check = next(c for c in report.checks if c.name == "tools_list")
    assert tools_check.passed is True


async def test_check_protocol_tools_list_failure() -> None:
    """check_protocol records a failed tools_list check when list_tools raises."""
    with _mock_server(_make_init_result(with_tools=True)) as session:
        session.list_tools = AsyncMock(side_effect=RuntimeError("timeout"))
        report = await check_protocol("python server.py")

    tools_check = next(c for c in report.checks if c.name == "tools_list")
    assert tools_check.passed is False


async def test_check_protocol_connection_failure() -> None:
    """check_protocol returns a failed report when the server cannot be reached."""
    mock_cm: MagicMock = MagicMock()
    mock_cm.__aenter__ = AsyncMock(side_effect=OSError("no such file"))

    with patch("mcpguard.checker.stdio_client", return_value=mock_cm):
        report = await check_protocol("nonexistent-server-binary")

    assert report.passed is False
    assert any(c.name == "server_connection" for c in report.checks)


async def test_check_protocol_routes_http_targets_to_http_checker() -> None:
    expected = ProtocolReport(
        target="https://example.test/mcp",
        server_name="modern",
        server_version="1.0",
        protocol_version="2026-07-28",
        checks=[CheckResult(name="server_discover", passed=True, message="ok")],
    )
    with patch(
        "mcpguard.checker.check_http_protocol",
        new=AsyncMock(return_value=expected),
    ) as http_check:
        result = await check_protocol("https://example.test/mcp", fuzz=True)
    assert result is expected
    http_check.assert_awaited_once_with(
        "https://example.test/mcp",
        fuzz=True,
        fuzz_max_calls=25,
        allow_dangerous_tools=False,
    )


async def test_http_checker_exercises_advertised_capabilities() -> None:
    client = MagicMock()
    client.discover = AsyncMock(
        return_value={
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "modern",
                    "version": "2.0",
                }
            },
        }
    )
    client.list_tools = AsyncMock(
        return_value=[
            {
                "name": "echo",
                "description": "Echo text",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ]
    )
    client.request = AsyncMock(return_value={})
    client.aclose = AsyncMock()

    with patch("mcpguard.checker.ModernHttpClient", return_value=client):
        report = await check_http_protocol("https://example.test/mcp")

    assert report.passed is True
    assert report.protocol_version == "2026-07-28"
    assert {check.name for check in report.checks} >= {
        "server_discover",
        "tools_list",
        "tool_security",
        "resources_list",
        "prompts_list",
    }
    client.request.assert_any_await("resources/list")
    client.request.assert_any_await("prompts/list")
    client.aclose.assert_awaited_once()


async def test_http_checker_returns_failed_report_on_connection_error() -> None:
    client = MagicMock()
    client.discover = AsyncMock(side_effect=OSError("offline"))
    client.aclose = AsyncMock()
    with patch("mcpguard.checker.ModernHttpClient", return_value=client):
        report = await check_http_protocol("https://example.test/mcp")
    assert report.passed is False
    assert report.checks[0].name == "http_connection"
    client.aclose.assert_awaited_once()
