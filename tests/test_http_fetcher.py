# --------------------------------------------------------------------------
# HTTP fetcher test module
# --------------------------------------------------------------------------
from unittest.mock import MagicMock, patch

import httpx
import pytest

from src.services.fetchers.http_fetcher import HTTPFetcher
from src.services.net_guard import ResolvedTarget, SSRFBlockedError


def _target(*ips, scheme="https", host="example.com", port=443):
    return ResolvedTarget(scheme=scheme, host=host, port=port, ips=ips)


@pytest.fixture(autouse=True)
def _bypass_ssrf_dns():
    """Avoid real DNS in unit tests; SSRF resolution is covered in test_net_guard."""
    with patch(
        "src.services.fetchers.http_fetcher.resolve_public_url",
        return_value=_target("93.184.216.34"),
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
                "src.services.fetchers.http_fetcher.resolve_public_url",
                side_effect=[_target("93.184.216.34"), None],
            ),
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            with pytest.raises(SSRFBlockedError):
                fetcher.fetch("https://example.com/")


class TestIPPinning:
    """Each hop connects to an address the SSRF guard resolved, so httpx never
    performs a second lookup that a short-TTL record could answer differently
    (DNS rebinding)."""

    @staticmethod
    def _pinned_client(*cms):
        mock_client = MagicMock()
        if len(cms) == 1:
            mock_client.stream.return_value = cms[0]
        else:
            mock_client.stream.side_effect = list(cms)
        return mock_client

    def test_connects_to_resolved_ip_with_original_host_and_sni(self):
        cm, _ = _stream_cm()
        mock_client = self._pinned_client(cm)

        with (
            patch(
                "src.services.fetchers.http_fetcher.httpx.Client",
                return_value=mock_client,
            ),
            patch(
                "src.services.fetchers.http_fetcher.settings.SSRF_GUARD_ENABLED", True
            ),
            patch(
                "src.services.fetchers.http_fetcher.resolve_public_url",
                return_value=_target("93.184.216.34"),
            ),
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            result = fetcher.fetch("https://example.com/a?q=1")

        call = mock_client.stream.call_args
        assert str(call.args[1]) == "https://93.184.216.34/a?q=1"
        # Virtual hosting and certificate validation still see the real host.
        assert call.kwargs["headers"]["Host"] == "example.com"
        assert call.kwargs["extensions"]["sni_hostname"] == "example.com"
        # The reported URL is the original host's, not the pinned literal.
        assert result is not None
        assert result.final_url == "https://example.com/a?q=1"

    def test_ipv6_address_is_bracketed(self):
        cm, _ = _stream_cm()
        mock_client = self._pinned_client(cm)

        with (
            patch(
                "src.services.fetchers.http_fetcher.httpx.Client",
                return_value=mock_client,
            ),
            patch(
                "src.services.fetchers.http_fetcher.settings.SSRF_GUARD_ENABLED", True
            ),
            patch(
                "src.services.fetchers.http_fetcher.resolve_public_url",
                return_value=_target("2606:2800:220:1:248:1893:25c8:1946"),
            ),
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            fetcher.fetch("https://example.com/a")

        call = mock_client.stream.call_args
        assert str(call.args[1]) == "https://[2606:2800:220:1:248:1893:25c8:1946]/a"
        assert call.kwargs["headers"]["Host"] == "example.com"

    def test_non_default_port_is_preserved_in_pinned_url_and_host(self):
        cm, _ = _stream_cm()
        mock_client = self._pinned_client(cm)

        with (
            patch(
                "src.services.fetchers.http_fetcher.httpx.Client",
                return_value=mock_client,
            ),
            patch(
                "src.services.fetchers.http_fetcher.settings.SSRF_GUARD_ENABLED", True
            ),
            patch(
                "src.services.fetchers.http_fetcher.resolve_public_url",
                return_value=_target("93.184.216.34", port=80),
            ),
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            fetcher.fetch("https://example.com:80/a")

        call = mock_client.stream.call_args
        assert str(call.args[1]) == "https://93.184.216.34:80/a"
        assert call.kwargs["headers"]["Host"] == "example.com:80"

    def test_no_pinning_when_guard_disabled(self):
        cm, _ = _stream_cm()
        mock_client = self._pinned_client(cm)

        with (
            patch(
                "src.services.fetchers.http_fetcher.httpx.Client",
                return_value=mock_client,
            ),
            patch(
                "src.services.fetchers.http_fetcher.settings.SSRF_GUARD_ENABLED", False
            ),
            patch(
                "src.services.fetchers.http_fetcher.resolve_public_url"
            ) as mock_resolve,
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            fetcher.fetch("https://example.com/a")

        mock_resolve.assert_not_called()
        call = mock_client.stream.call_args
        assert str(call.args[1]) == "https://example.com/a"
        assert call.kwargs["headers"] == {}
        assert call.kwargs["extensions"] == {}

    def test_relative_redirect_joins_against_original_host(self):
        """The Location header must resolve against the hostname URL; joining it
        onto the pinned literal would lose the host the next hop is validated
        under (and pin the follow-up to the previous hop's address)."""
        redirect_resp = MagicMock()
        redirect_resp.is_redirect = True
        redirect_resp.headers = {"location": "/next"}
        # httpx would report the pinned URL here; it must not drive the join.
        redirect_resp.url = httpx.URL("https://93.184.216.34/start")
        redirect_cm = MagicMock()
        redirect_cm.__enter__.return_value = redirect_resp
        redirect_cm.__exit__.return_value = False

        ok_cm, _ = _stream_cm()
        mock_client = self._pinned_client(redirect_cm, ok_cm)

        with (
            patch(
                "src.services.fetchers.http_fetcher.httpx.Client",
                return_value=mock_client,
            ),
            patch(
                "src.services.fetchers.http_fetcher.settings.SSRF_GUARD_ENABLED", True
            ),
            patch(
                "src.services.fetchers.http_fetcher.resolve_public_url",
                side_effect=[
                    _target("93.184.216.34"),
                    _target("93.184.216.35"),
                ],
            ) as mock_resolve,
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            result = fetcher.fetch("https://example.com/start")

        # Second hop is resolved under the original hostname...
        assert mock_resolve.call_args_list[1].args[0] == "https://example.com/next"
        # ...and pinned to that hop's own freshly resolved address.
        second_call = mock_client.stream.call_args_list[1]
        assert str(second_call.args[1]) == "https://93.184.216.35/next"
        assert second_call.kwargs["headers"]["Host"] == "example.com"
        assert result is not None
        assert result.final_url == "https://example.com/next"

    def test_cross_host_redirect_uses_new_host_for_header_and_sni(self):
        redirect_resp = MagicMock()
        redirect_resp.is_redirect = True
        redirect_resp.headers = {"location": "https://other.example.org/landing"}
        redirect_resp.url = httpx.URL("https://93.184.216.34/start")
        redirect_cm = MagicMock()
        redirect_cm.__enter__.return_value = redirect_resp
        redirect_cm.__exit__.return_value = False

        ok_cm, _ = _stream_cm()
        mock_client = self._pinned_client(redirect_cm, ok_cm)

        with (
            patch(
                "src.services.fetchers.http_fetcher.httpx.Client",
                return_value=mock_client,
            ),
            patch(
                "src.services.fetchers.http_fetcher.settings.SSRF_GUARD_ENABLED", True
            ),
            patch(
                "src.services.fetchers.http_fetcher.resolve_public_url",
                side_effect=[
                    _target("93.184.216.34"),
                    _target("198.51.100.7", host="other.example.org"),
                ],
            ),
        ):
            fetcher = HTTPFetcher(timeout=5.0)
            result = fetcher.fetch("https://example.com/start")

        second_call = mock_client.stream.call_args_list[1]
        assert str(second_call.args[1]) == "https://198.51.100.7/landing"
        assert second_call.kwargs["headers"]["Host"] == "other.example.org"
        assert second_call.kwargs["extensions"]["sni_hostname"] == "other.example.org"
        assert result is not None
        assert result.final_url == "https://other.example.org/landing"
