"""Tests for bounded, opt-in tool execution fuzzing."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

from mcpguard.fuzzer import fuzz_tools, generate_cases
from mcpguard.http_transport import McpProtocolError


def test_generate_cases_covers_valid_and_invalid_boundaries() -> None:
    cases = generate_cases(
        {
            "type": "object",
            "required": ["count", "name"],
            "properties": {
                "count": {"type": "integer", "minimum": 1, "maximum": 5},
                "name": {"type": "string", "minLength": 2, "maxLength": 4},
            },
            "additionalProperties": False,
        }
    )
    assert {} in cases
    assert any(case.get("count") == 1 for case in cases)
    assert any(case.get("count") == 5 for case in cases)
    assert len(cases) <= 12


async def test_fuzzer_skips_dangerous_tools_by_default() -> None:
    invoker = AsyncMock()
    tool = SimpleNamespace(
        name="delete_file",
        inputSchema={"type": "object", "properties": {}},
    )
    report = await fuzz_tools([tool], invoker)
    assert report.skipped == ["delete_file"]
    invoker.assert_not_called()


async def test_fuzzer_enforces_global_call_limit() -> None:
    invoker = AsyncMock(return_value={"content": []})
    tool = SimpleNamespace(
        name="echo",
        inputSchema={
            "type": "object",
            "properties": {"value": {"type": "string"}},
        },
    )
    report = await fuzz_tools([tool], invoker, max_calls=2)
    assert report.calls == 2
    assert report.failures == 0


async def test_fuzzer_records_crashes_without_stopping() -> None:
    invoker = AsyncMock(side_effect=RuntimeError("server crashed"))
    tool = SimpleNamespace(
        name="echo",
        inputSchema={"type": "object", "properties": {}},
    )
    report = await fuzz_tools([tool], invoker, max_calls=1)
    assert report.failures == 1
    assert "server crashed" in report.results[0].message


async def test_fuzzer_accepts_clean_protocol_rejection() -> None:
    invoker = AsyncMock(side_effect=McpProtocolError("invalid params"))
    tool = SimpleNamespace(
        name="echo",
        inputSchema={"type": "object", "properties": {}},
    )
    report = await fuzz_tools([tool], invoker, max_calls=1)
    assert report.failures == 0
    assert report.results[0].passed is True
