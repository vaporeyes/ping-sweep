# ABOUTME: Unit tests for scapy-based scanning functionality.
# ABOUTME: Tests ARP and TCP SYN scan methods.

import pytest
from unittest.mock import patch, MagicMock
from ping_sweep.scapy_scanner import (
    arp_scan_host,
    tcp_syn_scan_host,
    arp_sweep,
    tcp_syn_sweep,
    is_local_network,
    ScapyScanResult,
)


class TestIsLocalNetwork:
    """Tests for is_local_network using scapy routing table."""

    def test_local_network_when_no_gateway(self):
        # When scapy's routing table returns 0.0.0.0 as gateway, it's local
        mock_route = MagicMock()
        mock_route.route.return_value = ("en0", "192.168.1.100", "0.0.0.0")
        with patch("ping_sweep.scapy_scanner.conf", route=mock_route):
            assert is_local_network("192.168.1.50") is True

    def test_remote_network_when_has_gateway(self):
        # When scapy's routing table returns a gateway IP, it's not local
        mock_route = MagicMock()
        mock_route.route.return_value = ("en0", "192.168.1.100", "192.168.1.1")
        with patch("ping_sweep.scapy_scanner.conf", route=mock_route):
            assert is_local_network("10.0.0.1") is False

    def test_cidr_uses_first_ip_for_check(self):
        # For CIDR notation, check the network address
        mock_route = MagicMock()
        mock_route.route.return_value = ("en0", "192.168.1.100", "0.0.0.0")
        with patch("ping_sweep.scapy_scanner.conf", route=mock_route):
            assert is_local_network("192.168.1.0/24") is True
            # Verify we passed the network address to route()
            mock_route.route.assert_called_with("192.168.1.0")

    def test_handles_route_exception_gracefully(self):
        # If scapy's routing fails, assume not local (safer)
        mock_route = MagicMock()
        mock_route.route.side_effect = Exception("Routing error")
        with patch("ping_sweep.scapy_scanner.conf", route=mock_route):
            assert is_local_network("192.168.1.50") is False


class TestScapyScanResult:
    def test_result_dataclass(self):
        result = ScapyScanResult(
            ip="192.168.1.1",
            is_alive=True,
            method="arp",
            mac_address="aa:bb:cc:dd:ee:ff",
            rtt_ms=0.5,
        )
        assert result.ip == "192.168.1.1"
        assert result.is_alive is True
        assert result.method == "arp"
        assert result.mac_address == "aa:bb:cc:dd:ee:ff"
        assert result.rtt_ms == 0.5

    def test_result_defaults(self):
        result = ScapyScanResult(ip="10.0.0.1", is_alive=False, method="tcp_syn")
        assert result.mac_address is None
        assert result.rtt_ms is None
        assert result.port is None


class TestArpScanHost:
    @patch("ping_sweep.scapy_scanner.srp")
    def test_arp_scan_returns_result_on_response(self, mock_srp):
        # Simulate a successful ARP response
        mock_response = MagicMock()
        mock_response.hwsrc = "aa:bb:cc:dd:ee:ff"
        mock_response.time = 0.001

        mock_sent = MagicMock()
        mock_sent.sent_time = 0.0

        mock_srp.return_value = ([(mock_sent, mock_response)], [])

        result = arp_scan_host("192.168.1.1", timeout=1.0)

        assert result.ip == "192.168.1.1"
        assert result.is_alive is True
        assert result.method == "arp"
        assert result.mac_address == "aa:bb:cc:dd:ee:ff"

    @patch("ping_sweep.scapy_scanner.srp")
    def test_arp_scan_returns_not_alive_on_no_response(self, mock_srp):
        mock_srp.return_value = ([], [MagicMock()])

        result = arp_scan_host("192.168.1.2", timeout=1.0)

        assert result.ip == "192.168.1.2"
        assert result.is_alive is False
        assert result.method == "arp"
        assert result.mac_address is None


class TestTcpSynScanHost:
    @patch("ping_sweep.scapy_scanner.sr1")
    def test_tcp_syn_returns_alive_on_syn_ack(self, mock_sr1):
        # Simulate SYN-ACK response (flags = 0x12 = SYN+ACK)
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        mock_tcp = MagicMock()
        mock_tcp.flags = 0x12  # SYN-ACK
        mock_response.getlayer.return_value = mock_tcp
        mock_response.time = 0.002
        mock_sr1.return_value = mock_response

        with patch("ping_sweep.scapy_scanner._get_sent_time", return_value=0.0):
            result = tcp_syn_scan_host("192.168.1.1", port=80, timeout=1.0)

        assert result.ip == "192.168.1.1"
        assert result.is_alive is True
        assert result.method == "tcp_syn"
        assert result.port == 80

    @patch("ping_sweep.scapy_scanner.sr1")
    def test_tcp_syn_returns_alive_on_rst(self, mock_sr1):
        # RST response also means host is alive (just port closed)
        mock_response = MagicMock()
        mock_response.haslayer.return_value = True
        mock_tcp = MagicMock()
        mock_tcp.flags = 0x14  # RST-ACK
        mock_response.getlayer.return_value = mock_tcp
        mock_response.time = 0.001
        mock_sr1.return_value = mock_response

        with patch("ping_sweep.scapy_scanner._get_sent_time", return_value=0.0):
            result = tcp_syn_scan_host("192.168.1.1", port=443, timeout=1.0)

        assert result.is_alive is True

    @patch("ping_sweep.scapy_scanner.sr1")
    def test_tcp_syn_returns_not_alive_on_timeout(self, mock_sr1):
        mock_sr1.return_value = None

        result = tcp_syn_scan_host("192.168.1.2", port=80, timeout=1.0)

        assert result.ip == "192.168.1.2"
        assert result.is_alive is False
        assert result.method == "tcp_syn"


class TestArpSweep:
    @patch("ping_sweep.scapy_scanner.arp_scan_host")
    @pytest.mark.asyncio
    async def test_arp_sweep_yields_results(self, mock_scan):
        mock_scan.return_value = ScapyScanResult(
            ip="192.168.1.1", is_alive=True, method="arp"
        )

        results = []
        async for result in arp_sweep("192.168.1.1", timeout=1.0):
            results.append(result)

        assert len(results) == 1
        assert results[0].ip == "192.168.1.1"

    @patch("ping_sweep.scapy_scanner.arp_scan_host")
    @pytest.mark.asyncio
    async def test_arp_sweep_handles_range(self, mock_scan):
        mock_scan.side_effect = [
            ScapyScanResult(ip="192.168.1.1", is_alive=True, method="arp"),
            ScapyScanResult(ip="192.168.1.2", is_alive=False, method="arp"),
            ScapyScanResult(ip="192.168.1.3", is_alive=True, method="arp"),
        ]

        results = []
        async for result in arp_sweep("192.168.1.1-3", timeout=1.0):
            results.append(result)

        assert len(results) == 3


class TestTcpSynSweep:
    @patch("ping_sweep.scapy_scanner.tcp_syn_scan_host")
    @pytest.mark.asyncio
    async def test_tcp_syn_sweep_yields_results(self, mock_scan):
        mock_scan.return_value = ScapyScanResult(
            ip="192.168.1.1", is_alive=True, method="tcp_syn", port=80
        )

        results = []
        async for result in tcp_syn_sweep("192.168.1.1", ports=[80], timeout=1.0):
            results.append(result)

        assert len(results) == 1
        assert results[0].port == 80

    @patch("ping_sweep.scapy_scanner.tcp_syn_scan_host")
    @pytest.mark.asyncio
    async def test_tcp_syn_sweep_tries_multiple_ports(self, mock_scan):
        # First port fails, second succeeds
        mock_scan.side_effect = [
            ScapyScanResult(ip="192.168.1.1", is_alive=False, method="tcp_syn", port=80),
            ScapyScanResult(ip="192.168.1.1", is_alive=True, method="tcp_syn", port=443),
        ]

        results = []
        async for result in tcp_syn_sweep(
            "192.168.1.1", ports=[80, 443], timeout=1.0, stop_on_first=True
        ):
            results.append(result)

        # Should stop after finding alive host
        assert len(results) == 1
        assert results[0].is_alive is True


class TestCheckRootPrivileges:
    """Tests for cross-platform root/admin privilege checking."""

    def test_linux_root_returns_true(self):
        with patch("ping_sweep.scapy_scanner.platform.system", return_value="Linux"):
            with patch("ping_sweep.scapy_scanner.os.geteuid", return_value=0):
                from ping_sweep.scapy_scanner import check_root_privileges
                assert check_root_privileges() is True

    def test_linux_non_root_returns_false(self):
        with patch("ping_sweep.scapy_scanner.platform.system", return_value="Linux"):
            with patch("ping_sweep.scapy_scanner.os.geteuid", return_value=1000):
                from ping_sweep.scapy_scanner import check_root_privileges
                assert check_root_privileges() is False

    def test_macos_root_returns_true(self):
        with patch("ping_sweep.scapy_scanner.platform.system", return_value="Darwin"):
            with patch("ping_sweep.scapy_scanner.os.geteuid", return_value=0):
                from ping_sweep.scapy_scanner import check_root_privileges
                assert check_root_privileges() is True

    def test_windows_admin_returns_true(self):
        # Create mock ctypes.windll structure
        mock_windll = MagicMock()
        mock_windll.shell32.IsUserAnAdmin.return_value = 1
        with patch("ping_sweep.scapy_scanner.platform.system", return_value="Windows"):
            with patch("ping_sweep.scapy_scanner.ctypes") as mock_ctypes:
                mock_ctypes.windll = mock_windll
                from ping_sweep.scapy_scanner import check_root_privileges
                assert check_root_privileges() is True

    def test_windows_non_admin_returns_false(self):
        mock_windll = MagicMock()
        mock_windll.shell32.IsUserAnAdmin.return_value = 0
        with patch("ping_sweep.scapy_scanner.platform.system", return_value="Windows"):
            with patch("ping_sweep.scapy_scanner.ctypes") as mock_ctypes:
                mock_ctypes.windll = mock_windll
                from ping_sweep.scapy_scanner import check_root_privileges
                assert check_root_privileges() is False
