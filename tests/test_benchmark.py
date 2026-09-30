"""Tests for MCP latency benchmarking."""

from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest

from mcpguard.benchmark import benchmark_server


@asynccontextmanager
async def _session(_: str):
    yield object()


async def test_benchmark_collects_requested_samples() -> None:
    with patch("mcpguard.benchmark.stdio_session", _session):
        report = await benchmark_server("python server.py", iterations=3)
    assert report.iterations == 3
    assert len(report.samples_ms) == 3
    assert report.minimum_ms <= report.average_ms <= report.maximum_ms


async def test_benchmark_rejects_zero_iterations() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        await benchmark_server("python server.py", iterations=0)
