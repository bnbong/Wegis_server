# --------------------------------------------------------------------------
# SSRF guard test module
#
# Uses IP-literal hosts so getaddrinfo resolves without real network/DNS.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import socket
from unittest.mock import patch

from src.services.net_guard import resolve_public_url, validate_public_url


def _addrinfo(*ips, family=socket.AF_INET, port=443):
    """Build getaddrinfo-shaped tuples for the given addresses."""
    return [
        (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)) for ip in ips
    ]


class TestValidatePublicUrl:
    def test_allows_public_ip(self):
        assert validate_public_url("http://8.8.8.8/") is True
        assert validate_public_url("https://1.1.1.1/path") is True
        assert validate_public_url("https://93.184.216.34/") is True

    def test_allows_public_ipv6(self):
        """Global unicast IPv6 must keep passing: for IPv6 ``is_global`` is just
        the inverse of ``is_private``, so the CGNAT exclusion is IPv4-only.

        Resolution is mocked rather than leaning on IPv6 literals resolving on
        every CI runner.
        """
        for ip in (
            "2606:2800:220:1:248:1893:25c8:1946",
            "2001:4860:4860::8888",
            "2a00:1450:4001:80e::200e",
        ):
            infos = _addrinfo(ip, family=socket.AF_INET6)
            with patch("src.services.net_guard.socket.getaddrinfo", return_value=infos):
                assert validate_public_url("https://v6.example.com/") is True, ip

    def test_blocks_non_global_ipv6(self):
        for ip in (
            "fc00::1",  # unique local
            "fe80::1",  # link-local
            "ff02::1",  # multicast
            "2001:db8::1",  # documentation range
            "::ffff:127.0.0.1",  # IPv4-mapped loopback
        ):
            infos = _addrinfo(ip, family=socket.AF_INET6)
            with patch("src.services.net_guard.socket.getaddrinfo", return_value=infos):
                assert validate_public_url("https://v6.example.com/") is False, ip

    def test_blocks_loopback(self):
        assert validate_public_url("http://127.0.0.1/") is False
        assert validate_public_url("http://[::1]/") is False

    def test_blocks_private_ranges(self):
        assert validate_public_url("http://10.0.0.1/") is False
        assert validate_public_url("http://192.168.1.1/") is False
        assert validate_public_url("http://172.16.0.1/") is False

    def test_blocks_link_local_metadata(self):
        # AWS/GCP metadata endpoint
        assert validate_public_url("http://169.254.169.254/latest/meta-data/") is False

    def test_blocks_cgnat_shared_address_space(self):
        """RFC 6598 (100.64.0.0/10) is routed internally by cloud CNIs and
        carrier NATs, but trips none of is_private/is_reserved/etc."""
        assert validate_public_url("http://100.64.0.0/") is False
        assert validate_public_url("http://100.64.0.1/") is False
        assert validate_public_url("http://100.127.255.255/") is False

    def test_allows_addresses_bordering_cgnat(self):
        """The block must stop at the /10 boundary and not swallow neighbours."""
        assert validate_public_url("http://100.63.255.255/") is True
        assert validate_public_url("http://100.128.0.0/") is True

    def test_blocks_non_http_schemes(self):
        assert validate_public_url("ftp://8.8.8.8/") is False
        assert validate_public_url("file:///etc/passwd") is False
        assert validate_public_url("gopher://8.8.8.8/") is False

    def test_blocks_disallowed_ports(self):
        assert validate_public_url("http://8.8.8.8:22/") is False
        assert validate_public_url("http://8.8.8.8:6379/") is False

    def test_allows_standard_ports(self):
        assert validate_public_url("http://8.8.8.8:80/") is True
        assert validate_public_url("https://8.8.8.8:443/") is True


class TestResolvePublicUrl:
    """The resolved addresses are what the caller pins, so they must be the
    exact ones the guard inspected."""

    def test_returns_inspected_addresses(self):
        target = resolve_public_url("https://8.8.8.8/path")
        assert target is not None
        assert target.scheme == "https"
        assert target.host == "8.8.8.8"
        assert target.port == 443
        assert target.ips == ("8.8.8.8",)

    def test_defaults_port_per_scheme(self):
        http_target = resolve_public_url("http://8.8.8.8/")
        assert http_target is not None and http_target.port == 80

    def test_returns_none_for_internal_host(self):
        assert resolve_public_url("http://127.0.0.1/") is None
        assert resolve_public_url("http://169.254.169.254/") is None

    def test_returns_none_for_bad_scheme_or_port(self):
        assert resolve_public_url("ftp://8.8.8.8/") is None
        assert resolve_public_url("http://8.8.8.8:22/") is None

    def test_fails_closed_when_any_address_is_internal(self):
        """A split-horizon record mixing a public and an internal answer must
        be rejected outright, not pinned to the public one."""
        infos = _addrinfo("93.184.216.34", "169.254.169.254")
        with patch("src.services.net_guard.socket.getaddrinfo", return_value=infos):
            assert resolve_public_url("https://mixed.example.com/") is None

    def test_keeps_all_public_addresses_in_resolver_order(self):
        infos = _addrinfo("93.184.216.34", "93.184.216.35", "93.184.216.34")
        with patch("src.services.net_guard.socket.getaddrinfo", return_value=infos):
            target = resolve_public_url("https://multi.example.com/")
        assert target is not None
        # Duplicates (one per socktype) collapse; order is preserved.
        assert target.ips == ("93.184.216.34", "93.184.216.35")

    def test_returns_none_when_resolution_fails(self):
        with patch(
            "src.services.net_guard.socket.getaddrinfo", side_effect=socket.gaierror
        ):
            assert resolve_public_url("https://nxdomain.example.com/") is None
