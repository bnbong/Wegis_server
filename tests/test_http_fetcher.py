# --------------------------------------------------------------------------
# HTTP fetcher test module
# --------------------------------------------------------------------------
from unittest.mock import MagicMock, patch

from src.services.fetchers.http_fetcher import HTTPFetcher


def _stream_cm(content_type="text/html", body=b"<html>ok</html>", status=200):
    """Build a fake context manager mimicking httpx Client.stream(...)."""
    resp = MagicMock()
    resp.status_code = status
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
