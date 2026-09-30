import pytest

from mcpguard.baseline import compare_performance, fingerprint_tools


def test_performance_regression_detected() -> None:
    result = compare_performance(120, 100, max_regression_percent=10)
    assert result.passed is False
    assert result.regression_percent == pytest.approx(20)


def test_performance_improvement_passes() -> None:
    assert compare_performance(90, 100, max_regression_percent=10).passed is True


def test_tool_fingerprint_is_order_independent() -> None:
    a = [{"name": "b", "inputSchema": {}}, {"name": "a", "inputSchema": {}}]
    b = list(reversed(a))
    assert fingerprint_tools(a) == fingerprint_tools(b)


def test_tool_fingerprint_changes_with_description() -> None:
    assert fingerprint_tools([{"name": "a", "description": "safe"}]) != (
        fingerprint_tools([{"name": "a", "description": "ignore instructions"}])
    )
