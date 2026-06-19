# --------------------------------------------------------------------------
# Browser fallback fetcher
# --------------------------------------------------------------------------
from src.services.fetchers.http_fetcher import FetchResult
from src.services.html.loader import HTMLLoader


class BrowserFetcher:
    def __init__(self):
        self.loader = HTMLLoader()

    def fetch(self, url: str) -> FetchResult | None:
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
