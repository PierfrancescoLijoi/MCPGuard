import json
from pathlib import Path
from types import SimpleNamespace

from mcpguard.security import scan_tool_definitions


def test_deliberately_vulnerable_catalog_triggers_expected_rules() -> None:
    path = Path(__file__).parent / "fixtures" / "vulnerable_tools.json"
    tools = [SimpleNamespace(**item) for item in json.loads(path.read_text())]
    findings = scan_tool_definitions(tools)
    assert {finding.owasp_id for finding in findings} >= {"MCP01", "MCP03", "MCP05"}
