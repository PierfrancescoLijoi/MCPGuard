"""Latency benchmark for MCP servers."""

from __future__ import annotations

import time
from dataclasses import dataclass

from mcpguard.transport import stdio_session


@dataclass(frozen=True)
class BenchmarkReport:
    """Latency measurements for safe, read-only MCP operations."""

    target: str
    iterations: int
    samples_ms: list[float]

    @property
    def minimum_ms(self) -> float:
        return min(self.samples_ms)

    @property
    def maximum_ms(self) -> float:
        return max(self.samples_ms)

    @property
    def average_ms(self) -> float:
        return sum(self.samples_ms) / len(self.samples_ms)


async def benchmark_server(target: str, iterations: int = 5) -> BenchmarkReport:
    """Measure initialize latency using a fresh server process per sample."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")

    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        async with stdio_session(target):
            samples.append((time.perf_counter() - started) * 1000)
    return BenchmarkReport(target=target, iterations=iterations, samples_ms=samples)
