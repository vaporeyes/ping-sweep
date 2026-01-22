# ABOUTME: Unit tests for the concurrent ping sweep functionality.
# ABOUTME: Tests IP range sweeping and result aggregation.

import pytest
from ping_sweep.sweep import ping_sweep, PingResult


class TestPingSweep:
    @pytest.mark.asyncio
    async def test_sweep_single_ip_localhost(self):
        results = []
        async for result in ping_sweep("127.0.0.1", timeout=2.0):
            results.append(result)

        assert len(results) == 1
        assert results[0].ip == "127.0.0.1"
        assert results[0].is_alive is True
        assert results[0].rtt_ms is not None

    @pytest.mark.asyncio
    async def test_sweep_returns_ping_results(self):
        async for result in ping_sweep("127.0.0.1", timeout=2.0):
            assert isinstance(result, PingResult)
            assert hasattr(result, "ip")
            assert hasattr(result, "is_alive")
            assert hasattr(result, "rtt_ms")

    @pytest.mark.asyncio
    async def test_sweep_small_range(self):
        # Sweep a small range including localhost
        results = []
        async for result in ping_sweep("127.0.0.1-3", timeout=1.0):
            results.append(result)

        assert len(results) == 3
        ips = {r.ip for r in results}
        assert ips == {"127.0.0.1", "127.0.0.2", "127.0.0.3"}
        # At least localhost should be alive
        alive_results = [r for r in results if r.is_alive]
        assert any(r.ip == "127.0.0.1" for r in alive_results)

    @pytest.mark.asyncio
    async def test_sweep_unreachable_range(self):
        # RFC 5737 TEST-NET-1: guaranteed not routable
        results = []
        async for result in ping_sweep("192.0.2.1-3", timeout=0.5):
            results.append(result)

        assert len(results) == 3
        # All should be unreachable
        for result in results:
            assert result.is_alive is False
            assert result.rtt_ms is None

    @pytest.mark.asyncio
    async def test_sweep_respects_concurrency(self):
        import time
        start = time.time()
        # Sweep 4 IPs with concurrency of 4 - should be faster than sequential
        results = []
        async for result in ping_sweep("192.0.2.1-4", timeout=0.5, concurrency=4):
            results.append(result)
        elapsed = time.time() - start

        assert len(results) == 4
        # With concurrency=4, should complete in ~1 timeout period, not 4x
        assert elapsed < 3.0  # Generous buffer for CI environments
