# --------------------------------------------------------------------------
# Domain checker test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import pytest

from src.services.domain_checker import DomainChecker, _extract_domain


class TestDomainExtraction:
    """Domain extraction function test"""

    def test_extract_domain_with_https(self):
        """HTTPS URL extraction test"""
        assert _extract_domain("https://google.com") == "google.com"
        assert _extract_domain("https://www.google.com") == "google.com"
        assert _extract_domain("https://mail.google.com") == "google.com"

    def test_extract_domain_with_http(self):
        """HTTP URL extraction test"""
        assert _extract_domain("http://example.com") == "example.com"
        assert _extract_domain("http://www.example.com") == "example.com"

    def test_extract_domain_without_protocol(self):
        """URL without protocol extraction test"""
        assert _extract_domain("google.com") == "google.com"
        assert _extract_domain("www.google.com") == "google.com"

    def test_extract_domain_with_path(self):
        """URL with path extraction test"""
        assert _extract_domain("https://google.com/search?q=test") == "google.com"
        assert _extract_domain("https://github.com/user/repo") == "github.com"

    def test_extract_domain_invalid_url(self):
        """Invalid URL handling test"""
        assert _extract_domain("invalid-url") is None
        assert _extract_domain("") is None
        assert _extract_domain("just-text") is None


class TestDomainChecker:
    """DomainChecker class test"""

    @pytest.mark.asyncio
    async def test_is_whitelisted_exact_match(self, domain_checker, mock_redis):
        """Whitelist exact match test"""
        mock_redis.sismember.return_value = True

        result = await domain_checker.is_whitelisted("https://google.com")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_whitelisted_no_match(self, domain_checker, mock_redis):
        """Whitelist match not found test"""
        mock_redis.sismember.return_value = False
        mock_redis.smembers.return_value = set()

        result = await domain_checker.is_whitelisted("https://phishing-site.com")

        assert result is False

    @pytest.mark.asyncio
    async def test_is_blacklisted_exact_match(self, domain_checker, mock_redis):
        """Blacklist exact match test"""
        mock_redis.sismember.return_value = True

        result = await domain_checker.is_blacklisted("https://malicious-site.com")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_whitelisted_pattern_match(self, domain_checker, mock_redis):
        """Whitelist pattern match test"""
        mock_redis.sismember.return_value = False  # exact match failed
        mock_redis.smembers.return_value = {"*.google.com", "*.github.com"}

        result = await domain_checker.is_whitelisted("https://mail.google.com")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_blacklisted_pattern_match(self, domain_checker, mock_redis):
        """Blacklist pattern match test"""
        mock_redis.sismember.return_value = False  # exact match failed
        mock_redis.smembers.return_value = {"*.phishing.com", "suspicious-*"}

        result = await domain_checker.is_blacklisted("https://fake.phishing.com")

        assert result is True

    @pytest.mark.asyncio
    async def test_get_domain_status_whitelist(self, domain_checker, mock_redis):
        """Domain status - whitelist test"""
        mock_redis.sismember.side_effect = [
            True,
            False,
        ]  # whitelist True, blacklist False

        status = await domain_checker.get_domain_status("https://google.com")

        assert status == "whitelist"

    @pytest.mark.asyncio
    async def test_get_domain_status_blacklist(self, domain_checker, mock_redis):
        """Domain status - blacklist test"""
        mock_redis.sismember.side_effect = [
            False,
            True,
        ]  # whitelist False, blacklist True

        status = await domain_checker.get_domain_status("https://malicious.com")

        assert status == "blacklist"

    @pytest.mark.asyncio
    async def test_get_domain_status_unknown(self, domain_checker, mock_redis):
        """Domain status - unknown test"""
        mock_redis.sismember.return_value = False
        mock_redis.smembers.return_value = set()

        status = await domain_checker.get_domain_status("https://unknown-site.com")

        assert status == "unknown"


class TestPatternMatching:
    """Pattern matching test"""

    def test_wildcard_pattern_matching(self):
        """Wildcard pattern matching test"""
        assert DomainChecker._match_pattern("mail.google.com", "*.google.com") is True
        assert DomainChecker._match_pattern("google.com", "*.google.com") is True
        assert DomainChecker._match_pattern("yahoo.com", "*.google.com") is False

    def test_fnmatch_pattern_matching(self):
        """fnmatch pattern matching test"""
        assert (
            DomainChecker._match_pattern("suspicious-site.com", "suspicious-*") is True
        )
        assert DomainChecker._match_pattern("normal-site.com", "suspicious-*") is False
