"""Latency benchmark for MCP servers."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
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


@dataclass(frozen=True)
class ThroughputReport:
    """Concurrent operation throughput and latency measurements."""

    requests: int
    completed: int
    errors: int
    duration_seconds: float
    latencies_ms: list[float]

    @property
    def requests_per_second(self) -> float:
        return self.requests / self.duration_seconds

    @property
    def p50_ms(self) -> float:
        return _percentile(self.latencies_ms, 0.50)

    @property
    def p95_ms(self) -> float:
        return _percentile(self.latencies_ms, 0.95)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction + 0.999) - 1))
    return ordered[index]


async def benchmark_throughput(
    operation: Callable[[], Awaitable[None]],
    *,
    requests: int = 100,
    concurrency: int = 10,
) -> ThroughputReport:
    """Run a bounded concurrent operation benchmark."""
    if requests < 1:
        raise ValueError("requests must be at least 1")
    if not 1 <= concurrency <= requests:
        raise ValueError("concurrency must be between 1 and requests")

    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    errors = 0

    async def run_one() -> None:
        nonlocal errors
        async with semaphore:
            started = time.perf_counter()
            try:
                await operation()
            except Exception:
                errors += 1
            finally:
                latencies.append((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    await asyncio.gather(*(run_one() for _ in range(requests)))
    duration = max(time.perf_counter() - started, 1e-9)
    return ThroughputReport(
        requests=requests,
        completed=requests - errors,
        errors=errors,
        duration_seconds=duration,
        latencies_ms=latencies,
    )


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
