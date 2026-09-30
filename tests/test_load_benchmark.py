"""Tests for concurrent HTTP throughput benchmarking."""

import asyncio

import pytest

from mcpguard.benchmark import benchmark_throughput


async def test_throughput_report_counts_requests_and_errors() -> None:
    calls = 0

    async def operation() -> None:
        nonlocal calls
        calls += 1
        call_number = calls
        await asyncio.sleep(0)
        if call_number == 3:
            raise RuntimeError("boom")

    report = await benchmark_throughput(operation, requests=5, concurrency=2)
    assert report.requests == 5
    assert report.completed == 4
    assert report.errors == 1
    assert report.requests_per_second > 0
    assert report.p95_ms >= report.p50_ms


async def test_throughput_rejects_invalid_concurrency() -> None:
    async def operation() -> None:
        return None

    with pytest.raises(ValueError, match="concurrency"):
        await benchmark_throughput(operation, requests=1, concurrency=0)
