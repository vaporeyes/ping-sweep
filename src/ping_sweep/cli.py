# ABOUTME: Command-line interface for the ping sweep tool.
# ABOUTME: Provides argument parsing and output formatting.

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Sequence

from .sweep import ping_sweep, PingResult
from .scapy_scanner import (
    arp_sweep,
    tcp_syn_sweep,
    ScapyScanResult,
    check_root_privileges,
)


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
        "-m", "--method",
        type=str,
        choices=["icmp", "arp", "tcp"],
        default="icmp",
        help="Scan method: icmp (default), arp (local network, fast), tcp (TCP SYN)",
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
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Export results to a JSON file",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Comma-separated ports for TCP SYN scan (default: 80,443,22,21,25,8080,8443)",
    )
    return parser.parse_args(args)


def format_result(result: PingResult | ScapyScanResult) -> str:
    """Format a ping result for human-readable display."""
    extra_info = ""

    # Add method-specific info
    if isinstance(result, ScapyScanResult):
        if result.mac_address:
            extra_info = f" [MAC: {result.mac_address}]"
        elif result.port:
            extra_info = f" [port {result.port}]"

    if result.is_alive:
        rtt = result.rtt_ms if result.rtt_ms else 0
        return f"{result.ip}: alive ({rtt:.2f} ms){extra_info}"
    else:
        return f"{result.ip}: unreachable"


def format_result_json(result: PingResult | ScapyScanResult) -> str:
    """Format a ping result as a JSON string."""
    data = {
        "ip": result.ip,
        "is_alive": result.is_alive,
        "rtt_ms": result.rtt_ms,
    }
    if isinstance(result, ScapyScanResult):
        data["method"] = result.method
        if result.mac_address:
            data["mac_address"] = result.mac_address
        if result.port:
            data["port"] = result.port
    return json.dumps(data)


def results_to_json(results: list[PingResult | ScapyScanResult]) -> str:
    """Convert a list of results to a JSON string with summary."""
    alive_count = sum(1 for r in results if r.is_alive)
    dead_count = len(results) - alive_count

    result_dicts = []
    for r in results:
        d = {"ip": r.ip, "is_alive": r.is_alive, "rtt_ms": r.rtt_ms}
        if isinstance(r, ScapyScanResult):
            d["method"] = r.method
            if r.mac_address:
                d["mac_address"] = r.mac_address
            if r.port:
                d["port"] = r.port
        result_dicts.append(d)

    data = {
        "results": result_dicts,
        "summary": {
            "total": len(results),
            "alive": alive_count,
            "dead": dead_count,
        },
    }
    return json.dumps(data, indent=2)


def _parse_ports(ports_str: str | None) -> list[int] | None:
    """Parse comma-separated ports string into list of ints."""
    if ports_str is None:
        return None
    return [int(p.strip()) for p in ports_str.split(",")]


async def async_main(args: argparse.Namespace) -> int:
    """Async main entry point."""
    all_results: list[PingResult | ScapyScanResult] = []

    # Check for root privileges if using scapy methods
    if args.method in ("arp", "tcp") and not check_root_privileges():
        print(
            f"Error: {args.method.upper()} scanning requires root privileges. "
            "Try running with sudo.",
            file=sys.stderr
        )
        return 1

    try:
        # Select the appropriate scanner
        if args.method == "arp":
            scanner = arp_sweep(
                args.target,
                timeout=args.timeout,
                concurrency=args.concurrency,
            )
        elif args.method == "tcp":
            ports = _parse_ports(args.ports)
            scanner = tcp_syn_sweep(
                args.target,
                ports=ports,
                timeout=args.timeout,
                concurrency=args.concurrency,
            )
        else:  # icmp (default)
            scanner = ping_sweep(
                args.target,
                timeout=args.timeout,
                concurrency=args.concurrency,
            )

        async for result in scanner:
            # Filter if alive-only mode
            if args.alive_only and not result.is_alive:
                continue

            all_results.append(result)

            # Print incrementally if not in JSON mode
            if not args.json:
                print(format_result(result))

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Calculate totals for summary
    alive_count = sum(1 for r in all_results if r.is_alive)
    total_count = len(all_results)

    # Output JSON to stdout if requested
    if args.json:
        print(results_to_json(all_results))
    else:
        print(f"\nSweep complete: {alive_count}/{total_count} hosts alive")

    # Export to file if requested
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(results_to_json(all_results))

    return 0


def main() -> None:
    """Main entry point for the CLI."""
    args = parse_args()
    exit_code = asyncio.run(async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
