# ABOUTME: IP range parsing utilities for the ping sweep tool.
# ABOUTME: Handles CIDR notation, dash ranges, and single IP addresses.

import ipaddress
from typing import Iterator


def expand_cidr(cidr: str) -> Iterator[str]:
    """Expand a CIDR notation string into individual IP addresses."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network:
            yield str(ip)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}") from e


def _is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _ip_to_int(ip: str) -> int:
    """Convert an IP address string to an integer."""
    return int(ipaddress.ip_address(ip))


def _int_to_ip(num: int) -> str:
    """Convert an integer to an IP address string."""
    return str(ipaddress.ip_address(num))


def parse_ip_range(ip_range: str) -> Iterator[str]:
    """Parse an IP range specification into individual IP addresses.

    Supports:
    - Single IP: "192.168.1.1"
    - CIDR notation: "192.168.1.0/24"
    - Dash range: "192.168.1.1-192.168.1.10"
    - Short dash range: "192.168.1.1-10"
    """
    ip_range = ip_range.strip()

    # CIDR notation
    if "/" in ip_range:
        yield from expand_cidr(ip_range)
        return

    # Dash range
    if "-" in ip_range:
        parts = ip_range.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {ip_range}")

        start_ip = parts[0].strip()
        end_part = parts[1].strip()

        if not _is_valid_ip(start_ip):
            raise ValueError(f"Invalid start IP: {start_ip}")

        # Check if end is a full IP or just the last octet
        if _is_valid_ip(end_part):
            end_ip = end_part
        else:
            # Short form: "192.168.1.1-10" means 192.168.1.1 to 192.168.1.10
            if not end_part.isdigit():
                raise ValueError(f"Invalid range end: {end_part}")
            octets = start_ip.split(".")
            octets[3] = end_part
            end_ip = ".".join(octets)
            if not _is_valid_ip(end_ip):
                raise ValueError(f"Invalid end IP: {end_ip}")

        start_int = _ip_to_int(start_ip)
        end_int = _ip_to_int(end_ip)

        if start_int > end_int:
            raise ValueError(f"Start IP must be <= end IP: {start_ip} > {end_ip}")

        for ip_int in range(start_int, end_int + 1):
            yield _int_to_ip(ip_int)
        return

    # Single IP
    if _is_valid_ip(ip_range):
        yield ip_range
        return

    raise ValueError(f"Invalid IP range format: {ip_range}")
