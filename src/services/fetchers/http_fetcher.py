# --------------------------------------------------------------------------
# HTTP fast path fetcher
# --------------------------------------------------------------------------
import logging
from dataclasses import dataclass

import httpx

from src.core.config import settings
from src.services.net_guard import SSRFBlockedError, validate_public_url


logger = logging.getLogger("main")

# Content types that the HTML phishing model can meaningfully analyse.
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


def is_html_content_type(content_type: str | None) -> bool:
    """Return True if the Content-Type denotes an HTML document.

    A charset suffix is tolerated (e.g. ``text/html; charset=utf-8`` matches the
    ``text/html`` prefix). A missing/unknown content type is treated as HTML
    (lenient) so servers that omit the header are still analysed rather than
    silently skipped.
    """
    if not content_type:
        return True
    main_type = content_type.split(";", 1)[0].strip().lower()
    return main_type in _HTML_CONTENT_TYPES


@dataclass
class FetchResult:
    html: str
    fetch_mode: str
    status_code: int | None = None
    final_url: str | None = None
    content_type: str | None = None


class HTTPFetcher:
    def __init__(self, timeout: float = 8.0, max_bytes: int | None = None):
        self.timeout = timeout
        self.max_bytes = (
            max_bytes if max_bytes is not None else settings.HTTP_FETCH_MAX_BYTES
        )
        self._client = httpx.Client(
            timeout=self.timeout,
            # Redirects are followed manually so each hop can be SSRF-validated.
            follow_redirects=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
            },
        )

    def _normalize_target_url(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        return f"https://{url}"

    def close(self) -> None:
        self._client.close()

    def fetch(self, url: str) -> FetchResult | None:
        current = self._normalize_target_url(url)
        try:
            for _ in range(settings.FETCH_MAX_REDIRECTS + 1):
                # SSRF guard: validate each hop before connecting (defeats
                # public->internal redirects). Raise so the caller can report a
                # distinct, observable source instead of a generic error.
                if settings.SSRF_GUARD_ENABLED and not validate_public_url(current):
                    raise SSRFBlockedError(current)

                # Stream so headers are available before the body is downloaded.
                with self._client.stream("GET", current) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            return None
                        current = str(response.url.join(location))
                        continue

                    if response.status_code >= 400:
                        return None

                    content_type = response.headers.get("content-type")
                    final_url = str(response.url)

                    # Non-HTML resources (image/svg/pdf/zip/binary) are NOT
                    # downloaded: we return after headers and close the connection,
                    # so the server never streams an untrusted binary into memory.
                    if not is_html_content_type(content_type):
                        return FetchResult(
                            html="",
                            fetch_mode="http",
                            status_code=response.status_code,
                            final_url=final_url,
                            content_type=content_type,
                        )

                    # HTML: read up to max_bytes only, then stop.
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) >= self.max_bytes:
                            del body[self.max_bytes :]
                            break

                    encoding = response.encoding or "utf-8"
                    html = bytes(body).decode(encoding, errors="replace")
                    if not html.strip():
                        return None

                    return FetchResult(
                        html=html,
                        fetch_mode="http",
                        status_code=response.status_code,
                        final_url=final_url,
                        content_type=content_type,
                    )

            logger.warning("Too many redirects for %s", url)
            return None
        except SSRFBlockedError:
            logger.warning("SSRF guard blocked fetch: %s", current)
            raise
        except Exception as exc:
            logger.warning("HTTP fetch failed for %s: %s", url, exc)
            return None
