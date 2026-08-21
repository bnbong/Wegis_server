# --------------------------------------------------------------------------
# Browser fallback fetcher
# --------------------------------------------------------------------------
import logging

from src.core.config import settings
from src.services.fetchers.http_fetcher import FetchResult, normalize_target_url
from src.services.html.loader import HTMLLoader
from src.services.net_guard import SSRFBlockedError, validate_public_url

logger = logging.getLogger("main")


class BrowserFetcher:
    def __init__(self):
        self.loader = HTMLLoader()

    def fetch(self, url: str) -> FetchResult | None:
        # The browser resolves DNS itself, so the HTTP path's connect-time IP
        # pinning cannot be applied here and a DNS-rebinding window survives
        # between this check and Chrome's own lookup. Turn BROWSER_FETCH_ENABLED
        # off where no egress firewall backstops that residual risk.
        if not settings.BROWSER_FETCH_ENABLED:
            logger.info("Browser fetch disabled, skipping fallback: %s", url)
            return None

        # Normalize first, then validate the exact string handed to the loader:
        # a host rewritten after validation (the loader used to force a "www."
        # prefix) would send the browser to a target the guard never inspected.
        # Selenium's own redirects are not hop-validated either; rely on an
        # egress firewall as defense-in-depth.
        target_url = normalize_target_url(url)
        if settings.SSRF_GUARD_ENABLED and not validate_public_url(target_url):
            logger.warning("SSRF guard blocked browser fetch: %s", target_url)
            raise SSRFBlockedError(target_url)
        html = self.loader.load(target_url)
        if not html:
            return None
        return FetchResult(
            html=html,
            fetch_mode="browser",
            status_code=None,
            final_url=None,
            content_type="text/html",
        )
