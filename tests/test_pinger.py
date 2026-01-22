# ABOUTME: Unit tests for the async ping functionality.
# ABOUTME: Tests host reachability checking and timeout behavior.

import errno
import pytest
from unittest.mock import patch, AsyncMock
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


class TestPingHostErrorHandling:
    """Tests for error handling, particularly EMFILE (too many open files)."""

    @pytest.mark.asyncio
    async def test_emfile_error_returns_none_gracefully(self):
        """EMFILE error should return None without crashing."""
        emfile_error = OSError(errno.EMFILE, "Too many open files")
        with patch("ping_sweep.pinger.asyncio.create_subprocess_exec", side_effect=emfile_error):
            result = await ping_host("192.168.1.1", timeout=1.0)
            assert result is None

    @pytest.mark.asyncio
    async def test_emfile_error_logs_warning(self, caplog):
        """EMFILE error should log a warning about reducing concurrency."""
        emfile_error = OSError(errno.EMFILE, "Too many open files")
        with patch("ping_sweep.pinger.asyncio.create_subprocess_exec", side_effect=emfile_error):
            import logging
            with caplog.at_level(logging.WARNING):
                await ping_host("192.168.1.1", timeout=1.0)
            assert "EMFILE" in caplog.text
            assert "reducing concurrency" in caplog.text.lower()

    @pytest.mark.asyncio
    async def test_enfile_error_returns_none_gracefully(self):
        """ENFILE (system file limit) error should return None without crashing."""
        enfile_error = OSError(errno.ENFILE, "Too many open files in system")
        with patch("ping_sweep.pinger.asyncio.create_subprocess_exec", side_effect=enfile_error):
            result = await ping_host("192.168.1.1", timeout=1.0)
            assert result is None

    @pytest.mark.asyncio
    async def test_enfile_error_logs_warning(self, caplog):
        """ENFILE error should log a warning about reducing concurrency."""
        enfile_error = OSError(errno.ENFILE, "Too many open files in system")
        with patch("ping_sweep.pinger.asyncio.create_subprocess_exec", side_effect=enfile_error):
            import logging
            with caplog.at_level(logging.WARNING):
                await ping_host("192.168.1.1", timeout=1.0)
            assert "ENFILE" in caplog.text
            assert "reducing concurrency" in caplog.text.lower()

    @pytest.mark.asyncio
    async def test_generic_oserror_returns_none(self):
        """Generic OSError should return None without crashing."""
        generic_error = OSError("Generic OS error")
        with patch("ping_sweep.pinger.asyncio.create_subprocess_exec", side_effect=generic_error):
            result = await ping_host("192.168.1.1", timeout=1.0)
            assert result is None
