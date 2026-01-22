# ABOUTME: Concurrent ping sweep implementation.
# ABOUTME: Coordinates async ping operations across IP ranges.

import asyncio
from typing import AsyncIterator, Iterator
from dataclasses import dataclass

from .ip_range import parse_ip_range
from .pinger import ping_host


@dataclass
class PingResult:
    """Result of a ping operation."""
    ip: str
    is_alive: bool
    rtt_ms: float | None = None


async def _ping_one(ip: str, timeout: float) -> PingResult:
    """Ping a single IP and return a PingResult."""
    rtt = await ping_host(ip, timeout=timeout)
    return PingResult(
        ip=ip,
        is_alive=rtt is not None,
        rtt_ms=rtt,
    )


def _batch_iterator(iterator: Iterator[str], batch_size: int) -> Iterator[list[str]]:
    """Yield batches from an iterator without consuming it all upfront."""
    batch = []
    for item in iterator:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


async def ping_sweep(
    ip_range: str,
    timeout: float = 1.0,
    concurrency: int = 100
) -> AsyncIterator[PingResult]:
    """Sweep an IP range and yield results as they complete.

    Uses batched processing to avoid memory exhaustion on large ranges.
    Only creates tasks for `concurrency` IPs at a time.
    """
    ip_iter = parse_ip_range(ip_range)

    # Process IPs in batches to avoid OOM on large ranges
    for batch in _batch_iterator(ip_iter, concurrency):
        tasks = [asyncio.create_task(_ping_one(ip, timeout)) for ip in batch]

        # Yield results as they complete within this batch
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result
