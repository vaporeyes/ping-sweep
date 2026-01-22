# ABOUTME: Async ping implementation using system ping command.
# ABOUTME: Provides non-blocking host reachability checking.

import asyncio
import platform
import re
from typing import Optional


async def ping_host(host: str, timeout: float = 1.0) -> Optional[float]:
    """Ping a host and return the round-trip time in ms, or None if unreachable."""
    # Build platform-specific ping command
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        # macOS and Linux
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout + 1.0  # Extra buffer for process overhead
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None

        if proc.returncode != 0:
            return None

        # Parse RTT from output
        output = stdout.decode("utf-8", errors="ignore")
        return _parse_ping_rtt(output)

    except (OSError, asyncio.CancelledError):
        return None


def _parse_ping_rtt(output: str) -> Optional[float]:
    """Extract round-trip time from ping output."""
    # macOS/Linux format: "time=0.042 ms" or "time=42.1 ms"
    match = re.search(r"time[=<](\d+\.?\d*)\s*ms", output, re.IGNORECASE)
    if match:
        return float(match.group(1))

    # Windows format: "time=1ms" or "time<1ms"
    match = re.search(r"time[=<](\d+)ms", output, re.IGNORECASE)
    if match:
        return float(match.group(1))

    return None
