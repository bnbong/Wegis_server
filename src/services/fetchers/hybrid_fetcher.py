# --------------------------------------------------------------------------
# Hybrid fetcher: httpx first, browser fallback
# --------------------------------------------------------------------------
import re

from src.services.fetchers.browser_fetcher import BrowserFetcher
from src.services.fetchers.http_fetcher import (
    FetchResult,
    HTTPFetcher,
    is_html_content_type,
)


class HybridFetcher:
    def __init__(self, http_fetcher: HTTPFetcher | None = None):
        self.http_fetcher = http_fetcher or HTTPFetcher()
        self.browser_fetcher = BrowserFetcher()

    def close(self) -> None:
        self.http_fetcher.close()

    @staticmethod
    def _is_low_quality_html(html: str) -> bool:
        stripped = html.strip()
        if len(stripped) < 400:
            return True

        lowered = stripped.lower()
        if "<html" not in lowered or "<body" not in lowered:
            return True

        text_chars = re.sub(r"<[^>]+>", "", stripped)
        if len(text_chars.strip()) < 120:
            return True

        return False

    def fetch(self, url: str) -> FetchResult | None:
        http_result = self.http_fetcher.fetch(url)
        if http_result is not None:
            # Non-HTML resources must never be escalated to the browser.
            if not is_html_content_type(http_result.content_type):
                return http_result
            if not self._is_low_quality_html(http_result.html):
                return http_result

        browser_result = self.browser_fetcher.fetch(url)
        if browser_result:
            return browser_result

        return http_result
