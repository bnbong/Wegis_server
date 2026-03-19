# --------------------------------------------------------------------------
# HTTP fast path fetcher
# --------------------------------------------------------------------------
import logging
from dataclasses import dataclass

import httpx


logger = logging.getLogger("main")


@dataclass
class FetchResult:
    html: str
    fetch_mode: str
    status_code: int | None = None
    final_url: str | None = None


class HTTPFetcher:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def _normalize_target_url(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        return f"https://{url}"

    def fetch(self, url: str) -> FetchResult | None:
        target = self._normalize_target_url(url)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                headers=headers,
            ) as client:
                response = client.get(target)
                if response.status_code >= 400:
                    return None
                html = response.text or ""
                if not html.strip():
                    return None

                return FetchResult(
                    html=html,
                    fetch_mode="http",
                    status_code=response.status_code,
                    final_url=str(response.url),
                )
        except Exception as exc:
            logger.warning("HTTP fetch failed for %s: %s", url, exc)
            return None
