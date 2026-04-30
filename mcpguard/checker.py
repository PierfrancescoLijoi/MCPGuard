"""Protocol compliance checker for MCP servers."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


@dataclass
class CheckResult:
    """Result of a single protocol check."""

    name: str
    passed: bool
    message: str


@dataclass
class ProtocolReport:
    """Aggregated result of all protocol checks for one MCP server."""

    target: str
    server_name: str | None
    server_version: str | None
    protocol_version: str | None
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True when every check in this report passed."""
        return bool(self.checks) and all(c.passed for c in self.checks)


async def check_protocol(target: str) -> ProtocolReport:
    """Run protocol compliance checks against an MCP server.

    Connects to the server via stdio, performs the initialize handshake,
    and validates the response against the MCP specification.

    Args:
        target: Shell command to launch the MCP server (e.g. "python server.py").

    Returns:
        A :class:`ProtocolReport` with the outcome of every check.

    Raises:
        ValueError: If *target* is empty.
    """
    parts = shlex.split(target)
    if not parts:
        raise ValueError("target command must not be empty")

    params = StdioServerParameters(command=parts[0], args=parts[1:])
    checks: list[CheckResult] = []

    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                try:
                    init_result = await session.initialize()
                except Exception as exc:
                    checks.append(
                        CheckResult(
                            name="initialize_handshake",
                            passed=False,
                            message=f"Initialize failed: {exc}",
                        )
                    )
                    return ProtocolReport(
                        target=target,
                        server_name=None,
                        server_version=None,
                        protocol_version=None,
                        checks=checks,
                    )

                checks.append(
                    CheckResult(
                        name="initialize_handshake",
                        passed=True,
                        message="Initialize handshake completed successfully",
                    )
                )

                protocol_version: str = init_result.protocolVersion
                checks.append(
                    CheckResult(
                        name="protocol_version_present",
                        passed=bool(protocol_version),
                        message=(
                            f"Protocol version: {protocol_version}"
                            if protocol_version
                            else "protocolVersion field is missing or empty"
                        ),
                    )
                )

                server_info = init_result.serverInfo
                checks.append(
                    CheckResult(
                        name="server_info_present",
                        passed=server_info is not None,
                        message=(
                            f"Server: {server_info.name} {server_info.version}"
                            if server_info
                            else "serverInfo field is missing"
                        ),
                    )
                )

                return ProtocolReport(
                    target=target,
                    server_name=server_info.name if server_info else None,
                    server_version=server_info.version if server_info else None,
                    protocol_version=protocol_version,
                    checks=checks,
                )

    except Exception as exc:
        checks.append(
            CheckResult(
                name="server_connection",
                passed=False,
                message=f"Could not connect to server: {exc}",
            )
        )
        return ProtocolReport(
            target=target,
            server_name=None,
            server_version=None,
            protocol_version=None,
            checks=checks,
        )