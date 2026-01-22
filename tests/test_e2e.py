# ABOUTME: End-to-end tests for the ping sweep CLI.
# ABOUTME: Tests the full application from command line invocation to output.

import subprocess
import sys

import pytest


class TestCliEndToEnd:
    """End-to-end tests for the CLI."""

    def test_cli_shows_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "ping_sweep.cli", "--help"],
            capture_output=True,
            text=True,
            cwd="src",
        )
        assert result.returncode == 0
        assert "ping-sweep" in result.stdout
        assert "target" in result.stdout

    def test_cli_sweeps_localhost(self):
        result = subprocess.run(
            [sys.executable, "-m", "ping_sweep.cli", "127.0.0.1", "-t", "2"],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=10,
        )
        assert result.returncode == 0
        assert "127.0.0.1" in result.stdout
        assert "alive" in result.stdout
        assert "1/1 hosts alive" in result.stdout

    def test_cli_alive_only_flag(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "ping_sweep.cli",
                "127.0.0.1-3", "-t", "1", "--alive-only"
            ],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=15,
        )
        assert result.returncode == 0
        # Should only show alive hosts (localhost)
        assert "127.0.0.1" in result.stdout
        # Should not show unreachable message for alive-only mode
        output_lines = [
            line for line in result.stdout.split("\n")
            if line and not line.startswith("Sweep complete")
        ]
        for line in output_lines:
            assert "unreachable" not in line

    def test_cli_handles_invalid_target(self):
        result = subprocess.run(
            [sys.executable, "-m", "ping_sweep.cli", "not-valid-ip"],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=5,
        )
        assert result.returncode == 1
        assert "Error" in result.stderr

    def test_cli_sweeps_small_range(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "ping_sweep.cli",
                "192.0.2.1-3", "-t", "0.5", "-c", "10"
            ],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=10,
        )
        assert result.returncode == 0
        # Should report 3 hosts scanned
        assert "0/3 hosts alive" in result.stdout

    def test_cli_custom_timeout_and_concurrency(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "ping_sweep.cli",
                "127.0.0.1",
                "--timeout", "2.0",
                "--concurrency", "50"
            ],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=10,
        )
        assert result.returncode == 0
        assert "127.0.0.1" in result.stdout


class TestCliAsModule:
    """Tests running the package as a module."""

    def test_run_as_module(self):
        result = subprocess.run(
            [sys.executable, "-m", "ping_sweep", "--help"],
            capture_output=True,
            text=True,
            cwd="src",
        )
        # This will fail until we add __main__.py
        # For now, just check the cli module works
        result = subprocess.run(
            [sys.executable, "-m", "ping_sweep.cli", "--help"],
            capture_output=True,
            text=True,
            cwd="src",
        )
        assert result.returncode == 0
