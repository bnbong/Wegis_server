# --------------------------------------------------------------------------
# HTTP fetcher test module
# --------------------------------------------------------------------------
from unittest.mock import MagicMock, patch

from src.services.fetchers.http_fetcher import HTTPFetcher


class TestHTTPFetcher:
    def test_reuses_client_and_closes_it(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>ok</html>"
        mock_response.url = "https://example.com"
        mock_client.get.return_value = mock_response

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
        assert mock_client_class.call_count == 1
        assert mock_client.get.call_count == 2
        mock_client.close.assert_called_once()
