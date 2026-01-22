# ABOUTME: Tests for scalability and memory efficiency of sweep operations.
# ABOUTME: Ensures batched processing to prevent OOM on large IP ranges.

import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from ping_sweep.sweep import ping_sweep, PingResult
from ping_sweep.scapy_scanner import arp_sweep, tcp_syn_sweep, ScapyScanResult


class TestSweepBatching:
    """Tests that sweep processes IPs in batches, not all at once."""

    @pytest.mark.asyncio
    async def test_does_not_convert_entire_range_to_list(self):
        """Verify that parse_ip_range result is NOT fully consumed upfront."""
        consumed_count = 0
        original_parse = None

        def tracking_generator(ip_range):
            nonlocal consumed_count
            # Import here to get the real function
            from ping_sweep.ip_range import parse_ip_range as real_parse
            for ip in real_parse(ip_range):
                consumed_count += 1
                yield ip

        with patch("ping_sweep.sweep.parse_ip_range", side_effect=tracking_generator):
            with patch("ping_sweep.sweep._ping_one") as mock_ping:
                # Make ping return immediately
                mock_ping.return_value = PingResult(ip="x", is_alive=False)

                # Start iterating but only take first result
                results = []
                async for result in ping_sweep("192.168.1.0/24", concurrency=10):
                    results.append(result)
                    if len(results) >= 1:
                        # After getting first result, check how many IPs were consumed
                        # With batching, should be at most concurrency * 2, not 256
                        break

        # With proper batching, we should NOT have consumed all 256 IPs
        # just to get the first result
        assert consumed_count <= 20, (
            f"Expected at most ~20 IPs consumed for first result with concurrency=10, "
            f"but {consumed_count} were consumed. Indicates all IPs loaded upfront."
        )

    @pytest.mark.asyncio
    async def test_concurrent_tasks_limited_to_concurrency_param(self):
        """Verify that active task count never exceeds concurrency limit."""
        max_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def mock_ping_one(ip: str, timeout: float) -> PingResult:
            nonlocal max_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent:
                    max_concurrent = current_concurrent

            # Simulate some work
            await asyncio.sleep(0.01)

            async with lock:
                current_concurrent -= 1

            return PingResult(ip=ip, is_alive=True, rtt_ms=1.0)

        with patch("ping_sweep.sweep._ping_one", side_effect=mock_ping_one):
            results = []
            async for result in ping_sweep("192.168.1.1-50", concurrency=5):
                results.append(result)

        assert len(results) == 50
        # Should never exceed concurrency limit
        assert max_concurrent <= 5, (
            f"Max concurrent tasks was {max_concurrent}, but concurrency=5. "
            "Tasks are not being properly limited."
        )

    @pytest.mark.asyncio
    async def test_batching_still_returns_all_results(self):
        """Verify batching doesn't lose any results."""
        with patch("ping_sweep.sweep._ping_one") as mock_ping:
            mock_ping.side_effect = lambda ip, timeout: PingResult(
                ip=ip, is_alive=True, rtt_ms=0.1
            )

            results = []
            async for result in ping_sweep("192.168.1.1-100", concurrency=10):
                results.append(result)

        assert len(results) == 100
        # Verify all IPs are present
        ips = {r.ip for r in results}
        expected_ips = {f"192.168.1.{i}" for i in range(1, 101)}
        assert ips == expected_ips

    @pytest.mark.asyncio
    async def test_batching_with_small_range_less_than_concurrency(self):
        """Verify batching works when range is smaller than concurrency."""
        with patch("ping_sweep.sweep._ping_one") as mock_ping:
            mock_ping.side_effect = lambda ip, timeout: PingResult(
                ip=ip, is_alive=True, rtt_ms=0.1
            )

            results = []
            async for result in ping_sweep("192.168.1.1-5", concurrency=100):
                results.append(result)

        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_early_termination_does_not_leak_tasks(self):
        """Verify that breaking out early doesn't leave orphaned tasks."""
        task_count = 0

        async def mock_ping_one(ip: str, timeout: float) -> PingResult:
            nonlocal task_count
            task_count += 1
            await asyncio.sleep(0.1)  # Slow ping
            return PingResult(ip=ip, is_alive=True, rtt_ms=1.0)

        with patch("ping_sweep.sweep._ping_one", side_effect=mock_ping_one):
            results = []
            async for result in ping_sweep("192.168.1.1-100", concurrency=10):
                results.append(result)
                if len(results) >= 5:
                    break

        # Give time for any leaked tasks to complete
        await asyncio.sleep(0.2)

        # With batching, should have started at most ~concurrency tasks
        # not all 100
        assert task_count <= 20, (
            f"Started {task_count} tasks but only needed 5 results. "
            "Indicates tasks are being created eagerly instead of lazily."
        )


class TestScapySweepBatching:
    """Tests that scapy sweeps process IPs in batches."""

    @pytest.mark.asyncio
    async def test_arp_sweep_does_not_load_all_ips_upfront(self):
        """Verify ARP sweep uses batching."""
        consumed_count = 0

        def tracking_generator(ip_range):
            nonlocal consumed_count
            from ping_sweep.ip_range import parse_ip_range as real_parse
            for ip in real_parse(ip_range):
                consumed_count += 1
                yield ip

        with patch("ping_sweep.scapy_scanner.parse_ip_range", side_effect=tracking_generator):
            with patch("ping_sweep.scapy_scanner.arp_scan_host") as mock_scan:
                mock_scan.return_value = ScapyScanResult(
                    ip="x", is_alive=False, method="arp"
                )

                results = []
                async for result in arp_sweep("192.168.1.0/24", concurrency=10):
                    results.append(result)
                    if len(results) >= 1:
                        break

        # Should not consume all 256 IPs for first result
        assert consumed_count <= 20, (
            f"ARP sweep consumed {consumed_count} IPs upfront, expected <= 20"
        )

    @pytest.mark.asyncio
    async def test_tcp_syn_sweep_does_not_load_all_ips_upfront(self):
        """Verify TCP SYN sweep uses batching."""
        consumed_count = 0

        def tracking_generator(ip_range):
            nonlocal consumed_count
            from ping_sweep.ip_range import parse_ip_range as real_parse
            for ip in real_parse(ip_range):
                consumed_count += 1
                yield ip

        with patch("ping_sweep.scapy_scanner.parse_ip_range", side_effect=tracking_generator):
            with patch("ping_sweep.scapy_scanner.tcp_syn_scan_host") as mock_scan:
                mock_scan.return_value = ScapyScanResult(
                    ip="x", is_alive=False, method="tcp_syn"
                )

                results = []
                async for result in tcp_syn_sweep("192.168.1.0/24", concurrency=10):
                    results.append(result)
                    if len(results) >= 1:
                        break

        # Should not consume all 256 IPs for first result
        assert consumed_count <= 20, (
            f"TCP SYN sweep consumed {consumed_count} IPs upfront, expected <= 20"
        )

    @pytest.mark.asyncio
    async def test_arp_sweep_returns_all_results_with_batching(self):
        """Verify ARP sweep batching doesn't lose results."""
        with patch("ping_sweep.scapy_scanner.arp_scan_host") as mock_scan:
            mock_scan.side_effect = lambda ip, timeout: ScapyScanResult(
                ip=ip, is_alive=True, method="arp"
            )

            results = []
            async for result in arp_sweep("192.168.1.1-50", concurrency=10):
                results.append(result)

        assert len(results) == 50
        ips = {r.ip for r in results}
        expected_ips = {f"192.168.1.{i}" for i in range(1, 51)}
        assert ips == expected_ips
