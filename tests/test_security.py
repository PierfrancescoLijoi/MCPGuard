"""Tests for static MCP tool security checks."""

from types import SimpleNamespace

from mcpguard.security import scan_tool_definitions


def _tool(name: str, description: str = "Safe", **schema: object) -> SimpleNamespace:
    return SimpleNamespace(name=name, description=description, inputSchema=schema)


def test_strict_schema_has_no_findings() -> None:
    findings = scan_tool_definitions(
        [_tool("lookup", type="object", properties={}, additionalProperties=False)]
    )
    assert findings == []


def test_unbounded_schema_is_warning() -> None:
    findings = scan_tool_definitions([_tool("lookup", type="object")])
    assert any(
        f.rule == "unbounded-input" and f.severity == "warning" for f in findings
    )


def test_secret_description_is_error() -> None:
    findings = scan_tool_definitions(
        [
            _tool(
                "lookup",
                "Returns an API key",
                type="object",
                additionalProperties=False,
            )
        ]
    )
    assert any(
        f.rule == "secret-in-description" and f.severity == "error" for f in findings
    )


def test_dangerous_name_is_reported() -> None:
    findings = scan_tool_definitions(
        [_tool("shell_exec", type="object", additionalProperties=False)]
    )
    assert any(f.rule == "dangerous-tool-name" for f in findings)
