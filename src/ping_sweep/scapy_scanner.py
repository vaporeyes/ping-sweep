# ABOUTME: Scapy-based network scanning for host discovery.
# ABOUTME: Provides ARP scanning (local networks) and TCP SYN scanning.

import asyncio
import ctypes
import ipaddress
import os
import platform
import time
from dataclasses import dataclass
from typing import AsyncIterator, Iterator

from scapy.all import ARP, Ether, IP, TCP, sr1, srp, conf

from .ip_range import parse_ip_range

# Default ports for TCP SYN scan (common services likely to respond)
DEFAULT_TCP_PORTS = [80, 443, 22, 21, 25, 8080, 8443]


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


@dataclass
class ScapyScanResult:
    """Result of a scapy-based scan."""
    ip: str
    is_alive: bool
    method: str  # "arp" or "tcp_syn"
    mac_address: str | None = None
    rtt_ms: float | None = None
    port: int | None = None


def is_local_network(target: str) -> bool:
    """Check if target is on the local network using scapy's routing table.

    Uses scapy's routing table to determine if a target is reachable without
    going through a gateway, which indicates it's on the local network segment.
    This works correctly for any subnet mask, not just /24.
    """
    try:
        # Handle CIDR notation - use the network address for routing check
        if "/" in target:
            target_net = ipaddress.ip_network(target, strict=False)
            check_ip = str(target_net.network_address)
        else:
            check_ip = target

        # Use scapy's routing table to determine if target is local
        # route() returns (interface, output_ip, gateway_ip)
        # If gateway is 0.0.0.0, the target is on the local network segment
        route_result = conf.route.route(check_ip)
        gateway = route_result[2]
        return gateway == "0.0.0.0"
    except Exception:
        # On any error, assume not local (safer - don't attempt ARP)
        return False


def _get_sent_time() -> float:
    """Get the current time for RTT calculation."""
    return time.time()


def arp_scan_host(ip: str, timeout: float = 1.0) -> ScapyScanResult:
    """Perform ARP scan on a single host.

    ARP scanning only works on the local network but is very reliable
    since hosts must respond to ARP requests.

    Requires root/admin privileges.
    """
    start_time = time.time()

    # Create ARP request
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    try:
        answered, _ = srp(arp_request, timeout=timeout, verbose=False)

        if answered:
            # Got a response
            _, response = answered[0]
            rtt = (time.time() - start_time) * 1000  # Convert to ms
            return ScapyScanResult(
                ip=ip,
                is_alive=True,
                method="arp",
                mac_address=response.hwsrc,
                rtt_ms=rtt,
            )
    except Exception:
        pass

    return ScapyScanResult(ip=ip, is_alive=False, method="arp")


def tcp_syn_scan_host(
    ip: str,
    port: int = 80,
    timeout: float = 1.0
) -> ScapyScanResult:
    """Perform TCP SYN scan on a single host/port.

    Sends a SYN packet and looks for SYN-ACK or RST response.
    Both responses indicate the host is alive.

    Requires root/admin privileges.
    """
    start_time = time.time()

    # Create SYN packet
    syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")

    try:
        response = sr1(syn_packet, timeout=timeout, verbose=False)

        if response and response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            flags = tcp_layer.flags

            # SYN-ACK (0x12) or RST (0x04/0x14) both mean host is alive
            if flags & 0x12 == 0x12 or flags & 0x04:
                rtt = (time.time() - start_time) * 1000
                return ScapyScanResult(
                    ip=ip,
                    is_alive=True,
                    method="tcp_syn",
                    rtt_ms=rtt,
                    port=port,
                )
    except Exception:
        pass

    return ScapyScanResult(ip=ip, is_alive=False, method="tcp_syn", port=port)


async def arp_sweep(
    ip_range: str,
    timeout: float = 1.0,
    concurrency: int = 50
) -> AsyncIterator[ScapyScanResult]:
    """Sweep an IP range using ARP scanning.

    ARP scanning is fast and reliable for local networks.
    Hosts cannot block ARP requests on the local network.

    Uses batched processing to avoid memory exhaustion on large ranges.
    Uses the default executor to avoid thread pool creation overhead.
    Requires root/admin privileges.
    """
    ip_iter = parse_ip_range(ip_range)

    async def scan_one(ip: str) -> ScapyScanResult:
        loop = asyncio.get_running_loop()
        # Use default executor (None) to avoid creating new thread pools
        return await loop.run_in_executor(
            None, arp_scan_host, ip, timeout
        )

    # Process in batches to avoid OOM on large ranges
    for batch in _batch_iterator(ip_iter, concurrency):
        tasks = [asyncio.create_task(scan_one(ip)) for ip in batch]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result


async def tcp_syn_sweep(
    ip_range: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    concurrency: int = 50,
    stop_on_first: bool = True
) -> AsyncIterator[ScapyScanResult]:
    """Sweep an IP range using TCP SYN scanning.

    Tries multiple ports per host. If stop_on_first is True,
    stops scanning a host once it responds on any port.

    Uses batched processing to avoid memory exhaustion on large ranges.
    Uses the default executor to avoid thread pool creation overhead.
    Requires root/admin privileges.
    """
    if ports is None:
        ports = DEFAULT_TCP_PORTS

    ip_iter = parse_ip_range(ip_range)

    async def scan_host_first_alive(ip: str) -> ScapyScanResult:
        """Scan a single host, return on first alive port."""
        loop = asyncio.get_running_loop()

        for port in ports:
            # Use default executor (None) to avoid creating new thread pools
            result = await loop.run_in_executor(
                None, tcp_syn_scan_host, ip, port, timeout
            )
            if result.is_alive:
                return result

        # No response on any port
        return ScapyScanResult(ip=ip, is_alive=False, method="tcp_syn")

    async def scan_host_port(ip: str, port: int) -> ScapyScanResult:
        """Scan a single host/port combination."""
        loop = asyncio.get_running_loop()
        # Use default executor (None) to avoid creating new thread pools
        return await loop.run_in_executor(
            None, tcp_syn_scan_host, ip, port, timeout
        )

    # Process in batches to avoid OOM on large ranges
    if stop_on_first:
        for batch in _batch_iterator(ip_iter, concurrency):
            tasks = [asyncio.create_task(scan_host_first_alive(ip)) for ip in batch]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                yield result
    else:
        # Scan all ports for all hosts, batched by IP
        for batch in _batch_iterator(ip_iter, concurrency):
            for ip in batch:
                for port in ports:
                    result = await scan_host_port(ip, port)
                    yield result


def check_root_privileges() -> bool:
    """Check if we have root/admin privileges for raw sockets.

    Works on Linux, macOS (Darwin), and Windows.
    """
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    else:
        # Unix-like systems (Linux, macOS)
        return os.geteuid() == 0
