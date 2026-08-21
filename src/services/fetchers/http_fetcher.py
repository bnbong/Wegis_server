# --------------------------------------------------------------------------
# HTTP fast path fetcher
# --------------------------------------------------------------------------
import logging
from dataclasses import dataclass

import httpx

from src.core.config import settings
from src.services.net_guard import (
    ResolvedTarget,
    SSRFBlockedError,
    resolve_public_url,
)


logger = logging.getLogger("main")

# Content types that the HTML phishing model can meaningfully analyse.
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


def normalize_target_url(url: str) -> str:
    """Prefix a bare host with ``https://`` so the scheme is always explicit.

    Shared with the browser fallback so both fetch paths validate and request
    the exact same string: a URL rewritten after validation could reach a host
    the SSRF guard never inspected.
    """
    if url.startswith(("http://", "https://")):
        return url
    return f"https://{url}"


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
            # Pooled connections are keyed by (scheme, host, port), and a pinned
            # hop's host is an IP literal — so two hostnames sharing one address
            # would share a connection whose TLS handshake (SNI, certificate)
            # was done for whichever host opened it. No keep-alive means every
            # hop gets a connection matched to its own host.
            limits=httpx.Limits(max_keepalive_connections=0),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
            },
        )

    @staticmethod
    def _pin_to_resolved_ip(
        url: httpx.URL, target: ResolvedTarget
    ) -> tuple[httpx.URL, dict[str, str], dict[str, str]]:
        """Rewrite ``url``'s host to an address the SSRF guard already inspected.

        Returns the request URL plus the headers and extensions that keep the
        original host visible where it matters: ``Host`` for virtual hosting and
        ``sni_hostname`` so httpcore hands the real name to the TLS handshake
        and validates the certificate against it. Without this the connection
        would be established from a second, unchecked DNS lookup.
        """
        # netloc/raw_host are httpx's own ASCII (IDNA-encoded) forms, i.e. what
        # would have gone on the wire had the host not been substituted.
        headers = {"Host": url.netloc.decode("ascii")}
        extensions = {"sni_hostname": url.raw_host.decode("ascii")}
        return url.copy_with(host=target.ips[0]), headers, extensions

    def close(self) -> None:
        self._client.close()

    def fetch(self, url: str) -> FetchResult | None:
        current = normalize_target_url(url)
        try:
            for _ in range(settings.FETCH_MAX_REDIRECTS + 1):
                request_url = httpx.URL(current)
                headers: dict[str, str] = {}
                extensions: dict[str, str] = {}

                # SSRF guard: resolve each hop before connecting (defeats
                # public->internal redirects). Raise so the caller can report a
                # distinct, observable source instead of a generic error.
                if settings.SSRF_GUARD_ENABLED:
                    target = resolve_public_url(current)
                    if target is None:
                        raise SSRFBlockedError(current)
                    request_url, headers, extensions = self._pin_to_resolved_ip(
                        request_url, target
                    )

                # Stream so headers are available before the body is downloaded.
                with self._client.stream(
                    "GET", request_url, headers=headers, extensions=extensions
                ) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            return None
                        # Join against the original-host URL, never the pinned
                        # one: a relative Location resolved against the IP
                        # literal would lose the hostname the next hop must be
                        # resolved and validated under.
                        current = str(httpx.URL(current).join(location))
                        continue

                    if response.status_code >= 400:
                        return None

                    content_type = response.headers.get("content-type")
                    # ``response.url`` carries the pinned IP, so report the hop's
                    # original-host URL instead.
                    final_url = current

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
