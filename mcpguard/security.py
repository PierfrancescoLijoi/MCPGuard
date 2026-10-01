"""Static security checks for MCP tool definitions."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from mcpguard.poisoning import normalize, scan_description


@dataclass(frozen=True)
class SecurityFinding:
    """A potentially unsafe property found in an MCP tool definition."""

    rule: str
    severity: str
    tool: str
    message: str
    owasp_id: str | None = None


_SENSITIVE_NAME_PARTS = (
    "exec",
    "shell",
    "command",
    "delete",
    "remove",
    "write",
    "upload",
    "download",
)
_SECRET_WORD = re.compile(
    r"\b(password|passwd|secret|api[_ -]?key|access[_ -]?token|private[_ -]?key)\b",
    re.IGNORECASE,
)
_INJECTION = re.compile(
    r"(?:ignore|disregard).{0,30}(?:instruction|system|previous)|"
    r"(?:send|upload|exfiltrat).{0,30}(?:secret|credential|token)|"
    r"do not (?:tell|reveal)|hidden instruction",
    re.IGNORECASE,
)


_POISONING_OWASP = {"sensitive-path": "MCP01", "exfiltration-target": "MCP01"}


def tool_input_schema(tool: Any) -> Any:
    """Return a tool's input schema from wire-style or SDK-style objects.

    mcp 1.x exposes ``inputSchema``; mcp 2.x renamed the attribute to ``input_schema``.
    """
    for attribute in ("inputSchema", "input_schema"):
        schema = getattr(tool, attribute, None)
        if schema is not None:
            return schema
    return None


def is_dangerous_tool_name(name: str) -> bool:
    """Return whether a tool name suggests side effects or command execution."""
    canonical = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(part in canonical for part in _SENSITIVE_NAME_PARTS)


def scan_tool_definitions(tools: Iterable[Any]) -> list[SecurityFinding]:
    """Inspect tool metadata and input schemas for common security hazards.

    This deliberately operates on declarations only: it never invokes a tool.
    Findings are deterministic and suitable for a CI gate.
    """
    findings: list[SecurityFinding] = []
    for tool in tools:
        name = str(getattr(tool, "name", "") or "")
        description = normalize(str(getattr(tool, "description", "") or ""))
        schema = tool_input_schema(tool)

        if is_dangerous_tool_name(name):
            findings.append(
                SecurityFinding(
                    rule="dangerous-tool-name",
                    severity="warning",
                    tool=name,
                    message=(
                        "Tool exposes a potentially destructive or command-execution "
                        "operation"
                    ),
                    owasp_id="MCP05",
                )
            )

        if _SECRET_WORD.search(description):
            findings.append(
                SecurityFinding(
                    rule="secret-in-description",
                    severity="error",
                    tool=name,
                    message="Tool description appears to mention secret material",
                    owasp_id="MCP01",
                )
            )

        if _INJECTION.search(description):
            findings.append(
                SecurityFinding(
                    rule="tool-poisoning",
                    severity="error",
                    tool=name,
                    message="Tool description contains prompt-injection indicators",
                    owasp_id="MCP03",
                )
            )

        for signal in scan_description(name, description):
            findings.append(
                SecurityFinding(
                    rule=signal.rule,
                    severity=signal.severity,
                    tool=name,
                    message=signal.message,
                    owasp_id=_POISONING_OWASP.get(signal.rule, "MCP03"),
                )
            )

        if not isinstance(schema, Mapping):
            findings.append(
                SecurityFinding(
                    rule="missing-input-schema",
                    severity="error",
                    tool=name,
                    message="Tool inputSchema is missing or is not an object",
                    owasp_id="MCP03",
                )
            )
            continue

        if schema.get("type") != "object":
            findings.append(
                SecurityFinding(
                    rule="invalid-input-schema",
                    severity="error",
                    tool=name,
                    message="Tool inputSchema must declare type 'object'",
                    owasp_id="MCP03",
                )
            )

        if schema.get("additionalProperties", True) is not False:
            findings.append(
                SecurityFinding(
                    rule="unbounded-input",
                    severity="warning",
                    tool=name,
                    message="Tool schema allows undeclared input properties",
                    owasp_id="MCP02",
                )
            )

    return findings
