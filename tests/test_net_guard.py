# --------------------------------------------------------------------------
# SSRF guard test module
#
# Uses IP-literal hosts so getaddrinfo resolves without real network/DNS.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from src.services.net_guard import validate_public_url


class TestValidatePublicUrl:
    def test_allows_public_ip(self):
        assert validate_public_url("http://8.8.8.8/") is True
        assert validate_public_url("https://1.1.1.1/path") is True

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
