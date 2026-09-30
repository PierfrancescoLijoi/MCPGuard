"""Static security checks for MCP tool definitions."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SecurityFinding:
    """A potentially unsafe property found in an MCP tool definition."""

    rule: str
    severity: str
    tool: str
    message: str


_SENSITIVE_NAME = re.compile(
    r"(?:^|[_-])(exec|shell|command|delete|remove|write|upload|download)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_WORD = re.compile(
    r"\b(password|passwd|secret|api[_ -]?key|access[_ -]?token|private[_ -]?key)\b",
    re.IGNORECASE,
)


def is_dangerous_tool_name(name: str) -> bool:
    """Return whether a tool name suggests side effects or command execution."""
    return _SENSITIVE_NAME.search(name) is not None


def scan_tool_definitions(tools: Iterable[Any]) -> list[SecurityFinding]:
    """Inspect tool metadata and input schemas for common security hazards.

    This deliberately operates on declarations only: it never invokes a tool.
    Findings are deterministic and suitable for a CI gate.
    """
    findings: list[SecurityFinding] = []
    for tool in tools:
        name = str(getattr(tool, "name", "") or "")
        description = str(getattr(tool, "description", "") or "")
        schema = getattr(tool, "inputSchema", None)

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
                )
            )

        if _SECRET_WORD.search(description):
            findings.append(
                SecurityFinding(
                    rule="secret-in-description",
                    severity="error",
                    tool=name,
                    message="Tool description appears to mention secret material",
                )
            )

        if not isinstance(schema, Mapping):
            findings.append(
                SecurityFinding(
                    rule="missing-input-schema",
                    severity="error",
                    tool=name,
                    message="Tool inputSchema is missing or is not an object",
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
                )
            )

        if schema.get("additionalProperties", True) is not False:
            findings.append(
                SecurityFinding(
                    rule="unbounded-input",
                    severity="warning",
                    tool=name,
                    message="Tool schema allows undeclared input properties",
                )
            )

    return findings
