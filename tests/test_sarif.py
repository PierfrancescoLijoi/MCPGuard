import json

from mcpguard.checker import CheckResult, ProtocolReport
from mcpguard.reporter import render_sarif


def test_sarif_is_github_compatible() -> None:
    report = ProtocolReport(
        target="server",
        server_name="bad",
        server_version="1",
        protocol_version="2026-07-28",
        checks=[CheckResult("tool_security", False, "MCP03: poisoned tool")],
    )
    data = json.loads(render_sarif(report))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "MCPGuard"
    assert data["runs"][0]["results"][0]["ruleId"] == "tool_security"
    assert data["runs"][0]["results"][0]["level"] == "error"
