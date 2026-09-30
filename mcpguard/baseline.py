"""Performance baselines and deterministic MCP tool fingerprints."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BaselineComparison:
    passed: bool
    current: float
    baseline: float
    regression_percent: float


def compare_performance(
    current: float, baseline: float, *, max_regression_percent: float
) -> BaselineComparison:
    if baseline <= 0:
        raise ValueError("baseline must be positive")
    if max_regression_percent < 0:
        raise ValueError("max regression percent must not be negative")
    regression = ((current - baseline) / baseline) * 100
    return BaselineComparison(
        passed=regression <= max_regression_percent,
        current=current,
        baseline=baseline,
        regression_percent=regression,
    )


def fingerprint_tools(tools: list[dict[str, Any]]) -> str:
    """Hash security-relevant tool metadata independent of list ordering."""
    normalized = sorted(tools, key=lambda tool: str(tool.get("name", "")))
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
