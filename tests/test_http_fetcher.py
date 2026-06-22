# --------------------------------------------------------------------------
# HTTP fetcher test module
# --------------------------------------------------------------------------
from unittest.mock import MagicMock, patch

import httpx
import pytest

from src.services.fetchers.http_fetcher import HTTPFetcher
from src.services.net_guard import SSRFBlockedError


@pytest.fixture(autouse=True)
def _bypass_ssrf_dns():
    """Avoid real DNS in unit tests; SSRF resolution is covered in test_net_guard."""
    with patch(
        "src.services.fetchers.http_fetcher.validate_public_url", return_value=True
    ):
        yield


def _stream_cm(content_type="text/html", body=b"<html>ok</html>", status=200):
    """Build a fake context manager mimicking httpx Client.stream(...)."""
    resp = MagicMock()
    resp.status_code = status
    resp.is_redirect = False
    resp.headers = {"content-type": content_type}
    resp.url = "https://example.com"
    resp.encoding = "utf-8"
    resp.iter_bytes.return_value = [body]
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm, resp


class TestHTTPFetcher:
    def test_reuses_client_and_closes_it(self):
        mock_client = MagicMock()
        cm, _ = _stream_cm()
        mock_client.stream.return_value = cm

        with patch(
            "src.services.fetchers.http_fetcher.httpx.Client",
            return_value=mock_client,
        ) as mock_client_class:
            fetcher = HTTPFetcher(timeout=5.0)
            first = fetcher.fetch("example.com")
            second = fetcher.fetch("example.com")
            fetcher.close()

        assert first is not None
        assert second is not None
        assert first.html == "<html>ok</html>"
        assert mock_client_class.call_count == 1
        assert mock_client.stream.call_count == 2
        mock_client.close.assert_called_once()

    def test_non_html_body_is_not_downloaded(self):
        """Non-HTML responses return after headers without reading the body."""
        mock_client = MagicMock()
        cm, resp = _stream_cm(content_type="application/pdf", body=b"%PDF-1.7...")
        mock_client.stream.return_value = cm

        with patch(
            "src.services.fetchers.http_fetcher.httpx.Client",
            return_value=mock_client,
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            result = fetcher.fetch("https://x.com/file.pdf")

        assert result is not None
        assert result.content_type == "application/pdf"
        assert result.html == ""
        resp.iter_bytes.assert_not_called()  # body never read

    def test_html_body_is_capped_at_max_bytes(self):
        mock_client = MagicMock()
        big = b"<html>" + b"a" * 10_000 + b"</html>"
        cm, _ = _stream_cm(body=big)
        mock_client.stream.return_value = cm

        with patch(
            "src.services.fetchers.http_fetcher.httpx.Client",
            return_value=mock_client,
        ):
            fetcher = HTTPFetcher(timeout=5.0, max_bytes=100)
            result = fetcher.fetch("https://x.com/")

        assert result is not None
        assert len(result.html) <= 100

    def test_redirect_to_internal_is_blocked(self):
        """A public URL that 3xx-redirects to an internal IP is rejected per hop."""
        redirect_resp = MagicMock()
        redirect_resp.is_redirect = True
        redirect_resp.headers = {"location": "http://169.254.169.254/"}
        redirect_resp.url = httpx.URL("http://example.com/")
        cm = MagicMock()
        cm.__enter__.return_value = redirect_resp
        cm.__exit__.return_value = False

        mock_client = MagicMock()
        mock_client.stream.return_value = cm

        with (
            patch(
                "src.services.fetchers.http_fetcher.httpx.Client",
                return_value=mock_client,
            ),
            patch(
                "src.services.fetchers.http_fetcher.settings.SSRF_GUARD_ENABLED", True
            ),
            # first hop (public) ok, redirect target (internal) rejected
            patch(
                "src.services.fetchers.http_fetcher.validate_public_url",
                side_effect=[True, False],
            ),
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            with pytest.raises(SSRFBlockedError):
                fetcher.fetch("https://example.com/")
