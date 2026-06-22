# --------------------------------------------------------------------------
# Browser fallback fetcher
# --------------------------------------------------------------------------
import logging

from src.core.config import settings
from src.services.fetchers.http_fetcher import FetchResult
from src.services.html.loader import HTMLLoader
from src.services.net_guard import SSRFBlockedError, validate_public_url

logger = logging.getLogger("main")


class BrowserFetcher:
    def __init__(self):
        self.loader = HTMLLoader()

    def fetch(self, url: str) -> FetchResult | None:
        # SSRF guard before launching the browser. Selenium's own redirects are
        # not hop-validated here; rely on an egress firewall as defense-in-depth.
        if settings.SSRF_GUARD_ENABLED and not validate_public_url(url):
            logger.warning("SSRF guard blocked browser fetch: %s", url)
            raise SSRFBlockedError(url)
        html = self.loader.load(url)
        if not html:
            return None
        return FetchResult(
            html=html,
            fetch_mode="browser",
            status_code=None,
            final_url=None,
            content_type="text/html",
        )
