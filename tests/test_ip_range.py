# ABOUTME: Unit tests for IP range parsing functionality.
# ABOUTME: Tests CIDR notation, IP ranges, and single IP parsing.

import pytest
from ping_sweep.ip_range import parse_ip_range, expand_cidr


class TestExpandCidr:
    def test_expands_slash_24_to_256_addresses(self):
        ips = list(expand_cidr("192.168.1.0/24"))
        assert len(ips) == 256
        assert ips[0] == "192.168.1.0"
        assert ips[255] == "192.168.1.255"

    def test_expands_slash_30_to_4_addresses(self):
        ips = list(expand_cidr("10.0.0.0/30"))
        assert len(ips) == 4
        assert ips == ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_expands_slash_32_to_single_address(self):
        ips = list(expand_cidr("8.8.8.8/32"))
        assert ips == ["8.8.8.8"]

    def test_invalid_cidr_raises_value_error(self):
        with pytest.raises(ValueError):
            list(expand_cidr("not.valid.cidr/24"))


class TestParseIpRange:
    def test_parses_single_ip(self):
        ips = list(parse_ip_range("192.168.1.1"))
        assert ips == ["192.168.1.1"]

    def test_parses_cidr_notation(self):
        ips = list(parse_ip_range("10.0.0.0/30"))
        assert len(ips) == 4

    def test_parses_dash_range(self):
        ips = list(parse_ip_range("192.168.1.1-192.168.1.5"))
        assert len(ips) == 5
        assert ips[0] == "192.168.1.1"
        assert ips[-1] == "192.168.1.5"

    def test_dash_range_single_octet(self):
        ips = list(parse_ip_range("192.168.1.10-15"))
        assert len(ips) == 6
        assert ips == [
            "192.168.1.10",
            "192.168.1.11",
            "192.168.1.12",
            "192.168.1.13",
            "192.168.1.14",
            "192.168.1.15",
        ]

    def test_invalid_ip_raises_value_error(self):
        with pytest.raises(ValueError):
            list(parse_ip_range("invalid"))

    def test_reversed_range_raises_value_error(self):
        with pytest.raises(ValueError):
            list(parse_ip_range("192.168.1.10-5"))
