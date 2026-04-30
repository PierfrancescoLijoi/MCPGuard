"""Protocol compliance checker for MCP servers."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

KNOWN_PROTOCOL_VERSIONS: frozenset[str] = frozenset({"2024-11-05", "2025-03-26"})


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
    and validates the response against the MCP specification. If the server
    declares tool, resource, or prompt capabilities, the corresponding list
    methods are also exercised.

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

                # 1. initialize_handshake
                checks.append(
                    CheckResult(
                        name="initialize_handshake",
                        passed=True,
                        message="Initialize handshake completed successfully",
                    )
                )

                # 2. protocol_version_present
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

                # 3. protocol_version_known
                checks.append(
                    CheckResult(
                        name="protocol_version_known",
                        passed=protocol_version in KNOWN_PROTOCOL_VERSIONS,
                        message=(
                            f"Protocol version {protocol_version!r} is recognised"
                            if protocol_version in KNOWN_PROTOCOL_VERSIONS
                            else (
                                f"Unknown protocol version {protocol_version!r}; "
                                f"known: {sorted(KNOWN_PROTOCOL_VERSIONS)}"
                            )
                        ),
                    )
                )

                # 4. server_info_present
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

                # 5. server_name_nonempty
                if server_info is not None:
                    checks.append(
                        CheckResult(
                            name="server_name_nonempty",
                            passed=bool(server_info.name),
                            message=(
                                f"Server name: {server_info.name!r}"
                                if server_info.name
                                else "serverInfo.name is empty"
                            ),
                        )
                    )

                # Capability-specific checks
                caps = init_result.capabilities

                # 6. tools/list
                if caps is not None and caps.tools is not None:
                    try:
                        await session.list_tools()
                        checks.append(
                            CheckResult(
                                name="tools_list",
                                passed=True,
                                message="tools/list responded successfully",
                            )
                        )
                    except Exception as exc:
                        checks.append(
                            CheckResult(
                                name="tools_list",
                                passed=False,
                                message=f"tools/list failed: {exc}",
                            )
                        )

                # 7. resources/list
                if caps is not None and caps.resources is not None:
                    try:
                        await session.list_resources()
                        checks.append(
                            CheckResult(
                                name="resources_list",
                                passed=True,
                                message="resources/list responded successfully",
                            )
                        )
                    except Exception as exc:
                        checks.append(
                            CheckResult(
                                name="resources_list",
                                passed=False,
                                message=f"resources/list failed: {exc}",
                            )
                        )

                # 8. prompts/list
                if caps is not None and caps.prompts is not None:
                    try:
                        await session.list_prompts()
                        checks.append(
                            CheckResult(
                                name="prompts_list",
                                passed=True,
                                message="prompts/list responded successfully",
                            )
                        )
                    except Exception as exc:
                        checks.append(
                            CheckResult(
                                name="prompts_list",
                                passed=False,
                                message=f"prompts/list failed: {exc}",
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