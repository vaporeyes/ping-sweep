# ABOUTME: Command-line interface for the ping sweep tool.
# ABOUTME: Provides argument parsing and output formatting.

import argparse
import asyncio
import sys
from typing import Sequence

from .sweep import ping_sweep, PingResult


def parse_args(args: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ping-sweep",
        description="Fast concurrent ping sweep utility for network discovery",
    )
    parser.add_argument(
        "target",
        help="IP range to sweep (e.g., 192.168.1.0/24, 192.168.1.1-100, or single IP)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds for each ping (default: 1.0)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=100,
        help="Maximum concurrent pings (default: 100)",
    )
    parser.add_argument(
        "-a", "--alive-only",
        action="store_true",
        help="Only show hosts that are alive",
    )
    return parser.parse_args(args)


def format_result(result: PingResult) -> str:
    """Format a ping result for display."""
    if result.is_alive:
        return f"{result.ip}: alive ({result.rtt_ms:.2f} ms)"
    else:
        return f"{result.ip}: unreachable"


async def async_main(args: argparse.Namespace) -> int:
    """Async main entry point."""
    alive_count = 0
    total_count = 0

    try:
        async for result in ping_sweep(
            args.target,
            timeout=args.timeout,
            concurrency=args.concurrency,
        ):
            total_count += 1
            if result.is_alive:
                alive_count += 1

            if args.alive_only and not result.is_alive:
                continue

            print(format_result(result))

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"\nSweep complete: {alive_count}/{total_count} hosts alive")
    return 0


def main() -> None:
    """Main entry point for the CLI."""
    args = parse_args()
    exit_code = asyncio.run(async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
