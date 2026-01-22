# ABOUTME: Integration tests for ping sweep components working together.
# ABOUTME: Tests full pipeline from IP parsing through to sweep results.

import pytest
from ping_sweep import parse_ip_range, ping_host, ping_sweep
from ping_sweep.sweep import PingResult


class TestIpRangeToPing:
    """Tests that IP range parsing integrates correctly with ping functionality."""

    @pytest.mark.asyncio
    async def test_parsed_ips_are_valid_for_ping(self):
        ips = list(parse_ip_range("127.0.0.1-3"))
        # Each parsed IP should be pingable (valid format)
        for ip in ips:
            result = await ping_host(ip, timeout=1.0)
            # We don't care if it's alive, just that it doesn't raise
            assert result is None or isinstance(result, float)

    @pytest.mark.asyncio
    async def test_cidr_expansion_works_with_ping(self):
        ips = list(parse_ip_range("127.0.0.0/30"))
        assert len(ips) == 4
        # Ping localhost
        result = await ping_host(ips[1], timeout=1.0)  # 127.0.0.1
        assert result is not None


class TestSweepIntegration:
    """Tests that sweep correctly uses ip_range and pinger."""

    @pytest.mark.asyncio
    async def test_sweep_uses_all_parsed_ips(self):
        results = []
        async for result in ping_sweep("192.0.2.1-5", timeout=0.5):
            results.append(result)

        # Should have results for all 5 IPs
        assert len(results) == 5
        ips = {r.ip for r in results}
        assert ips == {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}

    @pytest.mark.asyncio
    async def test_sweep_with_cidr_notation(self):
        results = []
        async for result in ping_sweep("192.0.2.0/30", timeout=0.5):
            results.append(result)

        assert len(results) == 4

    @pytest.mark.asyncio
    async def test_sweep_returns_correct_result_types(self):
        async for result in ping_sweep("127.0.0.1", timeout=2.0):
            assert isinstance(result, PingResult)
            assert isinstance(result.ip, str)
            assert isinstance(result.is_alive, bool)
            if result.is_alive:
                assert isinstance(result.rtt_ms, float)
            else:
                assert result.rtt_ms is None
