# ABOUTME: Unit tests for the async ping functionality.
# ABOUTME: Tests host reachability checking and timeout behavior.

import pytest
from ping_sweep.pinger import ping_host


class TestPingHost:
    @pytest.mark.asyncio
    async def test_ping_localhost_succeeds(self):
        # Localhost should always be reachable
        result = await ping_host("127.0.0.1", timeout=2.0)
        assert result is not None
        assert result >= 0  # RTT should be non-negative

    @pytest.mark.asyncio
    async def test_ping_unreachable_returns_none(self):
        # RFC 5737 TEST-NET-1: guaranteed not routable
        result = await ping_host("192.0.2.1", timeout=0.5)
        assert result is None

    @pytest.mark.asyncio
    async def test_ping_invalid_host_returns_none(self):
        result = await ping_host("999.999.999.999", timeout=0.5)
        assert result is None

    @pytest.mark.asyncio
    async def test_ping_respects_timeout(self):
        import time
        start = time.time()
        # Use a non-routable address with short timeout
        await ping_host("192.0.2.1", timeout=0.5)
        elapsed = time.time() - start
        # Should complete within timeout + small buffer
        assert elapsed < 1.5
