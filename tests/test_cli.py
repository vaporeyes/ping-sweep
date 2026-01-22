# ABOUTME: Unit tests for the CLI interface.
# ABOUTME: Tests argument parsing and output formatting.

import pytest
from ping_sweep.cli import parse_args, format_result
from ping_sweep.sweep import PingResult


class TestParseArgs:
    def test_parses_single_ip(self):
        args = parse_args(["192.168.1.1"])
        assert args.target == "192.168.1.1"

    def test_parses_cidr(self):
        args = parse_args(["10.0.0.0/24"])
        assert args.target == "10.0.0.0/24"

    def test_default_timeout(self):
        args = parse_args(["192.168.1.1"])
        assert args.timeout == 1.0

    def test_custom_timeout(self):
        args = parse_args(["--timeout", "2.5", "192.168.1.1"])
        assert args.timeout == 2.5

    def test_default_concurrency(self):
        args = parse_args(["192.168.1.1"])
        assert args.concurrency == 100

    def test_custom_concurrency(self):
        args = parse_args(["-c", "50", "192.168.1.1"])
        assert args.concurrency == 50

    def test_alive_only_flag(self):
        args = parse_args(["--alive-only", "192.168.1.1"])
        assert args.alive_only is True

    def test_default_alive_only_is_false(self):
        args = parse_args(["192.168.1.1"])
        assert args.alive_only is False


class TestFormatResult:
    def test_formats_alive_host(self):
        result = PingResult(ip="192.168.1.1", is_alive=True, rtt_ms=1.23)
        output = format_result(result)
        assert "192.168.1.1" in output
        assert "alive" in output.lower()
        assert "1.23" in output

    def test_formats_dead_host(self):
        result = PingResult(ip="192.168.1.2", is_alive=False, rtt_ms=None)
        output = format_result(result)
        assert "192.168.1.2" in output
        assert "down" in output.lower() or "unreachable" in output.lower()
