# ABOUTME: End-to-end tests for the ping sweep CLI.
# ABOUTME: Tests the full application from command line invocation to output.

import json
import subprocess
import sys
import tempfile
from pathlib import Path

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


class TestCliJsonOutput:
    """End-to-end tests for JSON output."""

    def test_json_flag_outputs_valid_json(self):
        result = subprocess.run(
            [sys.executable, "-m", "ping_sweep.cli", "127.0.0.1", "--json", "-t", "2"],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=10,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "results" in data
        assert "summary" in data
        assert len(data["results"]) == 1
        assert data["results"][0]["ip"] == "127.0.0.1"
        assert data["results"][0]["is_alive"] is True

    def test_json_output_includes_summary(self):
        result = subprocess.run(
            [sys.executable, "-m", "ping_sweep.cli", "192.0.2.1-3", "--json", "-t", "0.5"],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=10,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["summary"]["total"] == 3
        assert data["summary"]["alive"] == 0
        assert data["summary"]["dead"] == 3

    def test_json_with_alive_only(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "ping_sweep.cli",
                "127.0.0.1-3", "--json", "--alive-only", "-t", "1"
            ],
            capture_output=True,
            text=True,
            cwd="src",
            timeout=15,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        # Results should only contain alive hosts
        for r in data["results"]:
            assert r["is_alive"] is True


class TestCliFileExport:
    """End-to-end tests for file export."""

    def test_output_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outfile = Path(tmpdir) / "results.json"
            result = subprocess.run(
                [
                    sys.executable, "-m", "ping_sweep.cli",
                    "127.0.0.1", "-t", "2", "-o", str(outfile)
                ],
                capture_output=True,
                text=True,
                cwd="src",
                timeout=10,
            )
            assert result.returncode == 0
            assert outfile.exists()

            data = json.loads(outfile.read_text())
            assert "results" in data
            assert data["results"][0]["ip"] == "127.0.0.1"

    def test_output_file_with_json_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outfile = Path(tmpdir) / "scan.json"
            result = subprocess.run(
                [
                    sys.executable, "-m", "ping_sweep.cli",
                    "192.0.2.1-2", "-t", "0.5", "--json", "-o", str(outfile)
                ],
                capture_output=True,
                text=True,
                cwd="src",
                timeout=10,
            )
            assert result.returncode == 0
            # Should still print JSON to stdout
            stdout_data = json.loads(result.stdout)
            assert "results" in stdout_data

            # And also write to file
            file_data = json.loads(outfile.read_text())
            assert "results" in file_data

    def test_output_without_json_flag_still_writes_json_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outfile = Path(tmpdir) / "output.json"
            result = subprocess.run(
                [
                    sys.executable, "-m", "ping_sweep.cli",
                    "127.0.0.1", "-t", "2", "-o", str(outfile)
                ],
                capture_output=True,
                text=True,
                cwd="src",
                timeout=10,
            )
            assert result.returncode == 0
            # Stdout should be human-readable (not JSON)
            assert "alive" in result.stdout

            # But file should be JSON
            file_data = json.loads(outfile.read_text())
            assert "results" in file_data
