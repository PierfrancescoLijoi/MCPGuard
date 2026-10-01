"""Bounded, opt-in fuzzing for MCP tool input validation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from mcpguard.http_transport import McpProtocolError
from mcpguard.security import is_dangerous_tool_name, tool_input_schema

ToolInvoker = Callable[[str, dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class FuzzResult:
    tool: str
    arguments: dict[str, Any]
    passed: bool
    message: str


@dataclass
class FuzzReport:
    calls: int = 0
    failures: int = 0
    skipped: list[str] = field(default_factory=list)
    results: list[FuzzResult] = field(default_factory=list)


def _values_for_schema(schema: Mapping[str, Any]) -> list[Any]:
    kind = schema.get("type")
    if kind == "string":
        minimum = int(schema.get("minLength", 0))
        maximum = min(int(schema.get("maxLength", max(minimum, 16))), 128)
        return ["x" * minimum, "x" * maximum, ""]
    if kind in {"integer", "number"}:
        minimum = schema.get("minimum", 0)
        maximum = schema.get("maximum", minimum + 1)
        return [minimum, maximum, minimum - 1]
    if kind == "boolean":
        return [True, False]
    if kind == "array":
        return [[], [None]]
    return [None]


def generate_cases(schema: Mapping[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    """Generate bounded boundary cases from an object JSON Schema."""
    if limit < 1:
        raise ValueError("case limit must be at least 1")
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return [{}]

    baseline: dict[str, Any] = {}
    for name, definition in properties.items():
        if isinstance(definition, Mapping):
            baseline[str(name)] = _values_for_schema(definition)[0]

    cases: list[dict[str, Any]] = [{}, baseline]
    for name, definition in properties.items():
        if not isinstance(definition, Mapping):
            continue
        for value in _values_for_schema(definition):
            case = dict(baseline)
            case[str(name)] = value
            if case not in cases:
                cases.append(case)
            if len(cases) >= limit:
                return cases
    if schema.get("additionalProperties", True) is not False:
        cases.append({**baseline, "__mcpguard_unknown__": "unexpected"})
    return cases[:limit]


async def fuzz_tools(
    tools: Iterable[Any],
    invoke: ToolInvoker,
    *,
    max_calls: int = 25,
    timeout: float = 5.0,
    allow_dangerous: bool = False,
) -> FuzzReport:
    """Execute bounded schema-derived cases against tools with safety guardrails."""
    if not 1 <= max_calls <= 1000:
        raise ValueError("max_calls must be between 1 and 1000")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    report = FuzzReport()
    for tool in tools:
        name = str(getattr(tool, "name", "") or "")
        if is_dangerous_tool_name(name) and not allow_dangerous:
            report.skipped.append(name)
            continue
        schema = tool_input_schema(tool)
        cases = generate_cases(schema if isinstance(schema, Mapping) else {})
        for arguments in cases:
            if report.calls >= max_calls:
                return report
            report.calls += 1
            try:
                result = await asyncio.wait_for(invoke(name, arguments), timeout)
                is_error = bool(
                    result.get("isError", False)
                    if isinstance(result, Mapping)
                    else False
                )
                report.results.append(
                    FuzzResult(
                        tool=name,
                        arguments=arguments,
                        passed=True,
                        message=(
                            "Input rejected cleanly by tool"
                            if is_error
                            else "Completed"
                        ),
                    )
                )
            except McpProtocolError as exc:
                report.results.append(
                    FuzzResult(
                        tool=name,
                        arguments=arguments,
                        passed=True,
                        message=f"Input rejected cleanly: {exc}",
                    )
                )
            except Exception as exc:
                report.failures += 1
                report.results.append(
                    FuzzResult(
                        tool=name,
                        arguments=arguments,
                        passed=False,
                        message=str(exc),
                    )
                )
    return report
