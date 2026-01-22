# ABOUTME: Unit tests for the CLI interface.
# ABOUTME: Tests argument parsing and output formatting.

import json
import pytest
from ping_sweep.cli import parse_args, format_result, format_result_json, results_to_json
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


class TestParseArgsJson:
    def test_json_flag(self):
        args = parse_args(["--json", "192.168.1.1"])
        assert args.json is True

    def test_default_json_is_false(self):
        args = parse_args(["192.168.1.1"])
        assert args.json is False

    def test_output_file(self):
        args = parse_args(["-o", "results.json", "192.168.1.1"])
        assert args.output == "results.json"

    def test_output_file_long_form(self):
        args = parse_args(["--output", "scan.json", "192.168.1.1"])
        assert args.output == "scan.json"

    def test_default_output_is_none(self):
        args = parse_args(["192.168.1.1"])
        assert args.output is None


class TestFormatResultJson:
    def test_formats_alive_host_as_json(self):
        result = PingResult(ip="192.168.1.1", is_alive=True, rtt_ms=1.23)
        output = format_result_json(result)
        data = json.loads(output)
        assert data["ip"] == "192.168.1.1"
        assert data["is_alive"] is True
        assert data["rtt_ms"] == 1.23

    def test_formats_dead_host_as_json(self):
        result = PingResult(ip="192.168.1.2", is_alive=False, rtt_ms=None)
        output = format_result_json(result)
        data = json.loads(output)
        assert data["ip"] == "192.168.1.2"
        assert data["is_alive"] is False
        assert data["rtt_ms"] is None


class TestResultsToJson:
    def test_converts_results_list_to_json(self):
        results = [
            PingResult(ip="192.168.1.1", is_alive=True, rtt_ms=1.5),
            PingResult(ip="192.168.1.2", is_alive=False, rtt_ms=None),
        ]
        output = results_to_json(results)
        data = json.loads(output)

        assert "results" in data
        assert "summary" in data
        assert len(data["results"]) == 2
        assert data["summary"]["total"] == 2
        assert data["summary"]["alive"] == 1
        assert data["summary"]["dead"] == 1

    def test_json_output_is_valid_json(self):
        results = [PingResult(ip="10.0.0.1", is_alive=True, rtt_ms=0.5)]
        output = results_to_json(results)
        # Should not raise
        json.loads(output)


class TestParseArgsScanMethod:
    def test_default_scan_method_is_icmp(self):
        args = parse_args(["192.168.1.1"])
        assert args.method == "icmp"

    def test_arp_scan_method(self):
        args = parse_args(["--method", "arp", "192.168.1.1"])
        assert args.method == "arp"

    def test_tcp_syn_scan_method(self):
        args = parse_args(["-m", "tcp", "192.168.1.1"])
        assert args.method == "tcp"

    def test_ports_option(self):
        args = parse_args(["--ports", "80,443,8080", "192.168.1.1"])
        assert args.ports == "80,443,8080"

    def test_default_ports_is_none(self):
        args = parse_args(["192.168.1.1"])
        assert args.ports is None
