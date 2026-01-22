# ABOUTME: Concurrent ping sweep implementation.
# ABOUTME: Coordinates async ping operations across IP ranges.

import asyncio
from typing import AsyncIterator
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


async def ping_sweep(
    ip_range: str,
    timeout: float = 1.0,
    concurrency: int = 100
) -> AsyncIterator[PingResult]:
    """Sweep an IP range and yield results as they complete."""
    ips = list(parse_ip_range(ip_range))
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_ping(ip: str) -> PingResult:
        async with semaphore:
            return await _ping_one(ip, timeout)

    # Create all tasks
    tasks = [asyncio.create_task(bounded_ping(ip)) for ip in ips]

    # Yield results as they complete
    for coro in asyncio.as_completed(tasks):
        result = await coro
        yield result
