# --------------------------------------------------------------------------
# Browser fallback fetcher test module
#
# The browser cannot pin the address the SSRF guard resolved, so the one
# invariant it must hold is that the validated string and the string handed to
# ``driver.get`` are byte-for-byte identical.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from unittest.mock import MagicMock, patch

import pytest

from src.exceptions import BackendExceptions
from src.services.fetchers.browser_fetcher import BrowserFetcher
from src.services.html.loader import HTMLLoader
from src.services.net_guard import SSRFBlockedError


@pytest.fixture
def browser_fetcher():
    """BrowserFetcher whose HTMLLoader is mocked (no real WebDriver)."""
    with patch("src.services.fetchers.browser_fetcher.HTMLLoader") as loader_class:
        fetcher = BrowserFetcher()
        fetcher.loader.load.return_value = "<html><body>ok</body></html>"
        loader_class.assert_called_once()
        yield fetcher


class TestBrowserFetcherNormalization:
    def test_schemeless_url_gets_https_and_no_www_prefix(self, browser_fetcher):
        """The loader used to force a "www." host, which meant the guard checked
        example.com while Chrome visited www.example.com."""
        browser_fetcher.fetch("example.com/login")

        browser_fetcher.loader.load.assert_called_once_with("https://example.com/login")

    def test_absolute_url_is_passed_through_untouched(self, browser_fetcher):
        browser_fetcher.fetch("http://example.com/a?q=1")

        browser_fetcher.loader.load.assert_called_once_with("http://example.com/a?q=1")

    def test_validated_url_is_exactly_the_loaded_url(self, browser_fetcher):
        """Whatever the guard approved is what the browser must request."""
        with (
            patch(
                "src.services.fetchers.browser_fetcher.settings.SSRF_GUARD_ENABLED",
                True,
            ),
            patch(
                "src.services.fetchers.browser_fetcher.validate_public_url",
                return_value=True,
            ) as mock_validate,
        ):
            browser_fetcher.fetch("example.com")

        validated_url = mock_validate.call_args.args[0]
        loaded_url = browser_fetcher.loader.load.call_args.args[0]
        assert validated_url == loaded_url == "https://example.com"

    def test_returns_none_when_loader_yields_nothing(self, browser_fetcher):
        browser_fetcher.loader.load.return_value = ""

        assert browser_fetcher.fetch("https://example.com/") is None


class TestBrowserFetcherGuards:
    def test_blocked_url_raises_and_never_reaches_the_loader(self, browser_fetcher):
        with (
            patch(
                "src.services.fetchers.browser_fetcher.settings.SSRF_GUARD_ENABLED",
                True,
            ),
            patch(
                "src.services.fetchers.browser_fetcher.validate_public_url",
                return_value=False,
            ),
        ):
            with pytest.raises(SSRFBlockedError):
                browser_fetcher.fetch("http://169.254.169.254/latest/meta-data/")

        browser_fetcher.loader.load.assert_not_called()

    def test_disabled_flag_skips_the_browser_entirely(self, browser_fetcher):
        """BROWSER_FETCH_ENABLED=false is the opt-out for deployments without an
        egress firewall, since this path keeps a DNS-rebinding window."""
        with (
            patch(
                "src.services.fetchers.browser_fetcher.settings.BROWSER_FETCH_ENABLED",
                False,
            ),
            patch(
                "src.services.fetchers.browser_fetcher.settings.SSRF_GUARD_ENABLED",
                True,
            ),
            patch(
                "src.services.fetchers.browser_fetcher.validate_public_url"
            ) as mock_validate,
        ):
            result = browser_fetcher.fetch("https://example.com/")

        assert result is None
        mock_validate.assert_not_called()
        browser_fetcher.loader.load.assert_not_called()

    def test_enabled_flag_runs_the_fallback(self, browser_fetcher):
        with patch(
            "src.services.fetchers.browser_fetcher.settings.BROWSER_FETCH_ENABLED",
            True,
        ):
            result = browser_fetcher.fetch("https://example.com/")

        assert result is not None
        assert result.fetch_mode == "browser"
        browser_fetcher.loader.load.assert_called_once()


class TestHTMLLoader:
    @staticmethod
    def _loader_with_driver():
        loader = HTMLLoader()
        driver = MagicMock()
        loader._init_driver = MagicMock(return_value=driver)
        return loader, driver

    def test_url_reaches_driver_get_unchanged(self):
        loader, driver = self._loader_with_driver()

        loader.load("https://example.com/login?next=%2Fa")

        driver.get.assert_called_once_with("https://example.com/login?next=%2Fa")

    def test_host_is_never_rewritten_to_www(self):
        loader, driver = self._loader_with_driver()

        loader.load("https://example.com")

        assert driver.get.call_args.args[0] == "https://example.com"

    def test_schemeless_url_is_rejected_instead_of_guessed(self):
        """The loader must not invent a scheme: the caller validated a specific
        absolute URL and only that one may be requested."""
        loader, driver = self._loader_with_driver()

        with pytest.raises(BackendExceptions):
            loader.load("example.com")

        driver.get.assert_not_called()
