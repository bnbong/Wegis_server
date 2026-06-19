# --------------------------------------------------------------------------
# URL canonicalization & content-type classification test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from src.services.url_utils import canonicalize_url
from src.services.fetchers.http_fetcher import is_html_content_type


class TestCanonicalizeVolatileQuery:
    """Signed-URL params are stripped, but only for recognised signing schemes."""

    def test_strips_amz_signed_params(self):
        signed = (
            "https://kr.object.gov-ncloudstorage.com/bucket/proj1.pdf"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=abc"
            "&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600"
            "&X-Amz-Signature=deadbeef&X-Amz-SignedHeaders=host"
        )
        assert (
            canonicalize_url(signed)
            == "https://kr.object.gov-ncloudstorage.com/bucket/proj1.pdf"
        )

    def test_signed_urls_with_different_signatures_converge(self):
        a = "https://x.com/f.pdf?X-Amz-Signature=aaa&X-Amz-Expires=10&id=7"
        b = "https://x.com/f.pdf?X-Amz-Signature=bbb&X-Amz-Expires=99&id=7"
        assert canonicalize_url(a) == canonicalize_url(b)
        assert canonicalize_url(a) == "https://x.com/f.pdf?id=7"

    def test_amz_param_names_are_case_insensitive(self):
        url = "https://x.com/f.pdf?X-AMZ-SIGNATURE=aaa&X-Amz-Expires=10&id=7"
        assert canonicalize_url(url) == "https://x.com/f.pdf?id=7"

    def test_strips_gcs_v4_signed_params(self):
        url = (
            "https://storage.googleapis.com/b/o.bin"
            "?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=c"
            "&X-Goog-Date=d&X-Goog-Expires=900&X-Goog-Signature=sig&keep=1"
        )
        assert canonicalize_url(url) == "https://storage.googleapis.com/b/o.bin?keep=1"

    def test_strips_azure_sas_only_with_signature_pair(self):
        sas = "https://acct.blob.core.windows.net/c/b.bin?sv=2021-08-06&sig=abc&se=x&keep=1"
        assert (
            canonicalize_url(sas) == "https://acct.blob.core.windows.net/c/b.bin?keep=1"
        )

    def test_generic_token_params_are_preserved(self):
        # No recognised signing scheme -> distinct resources must NOT collapse.
        url = "https://x.com/d?token=abc&keep=1"
        assert canonicalize_url(url) == "https://x.com/d?keep=1&token=abc"
        a = canonicalize_url("https://x.com/d?token=benign")
        b = canonicalize_url("https://x.com/d?token=malware")
        assert a != b

    def test_bare_sig_without_sv_is_preserved(self):
        # "sig" alone (no Azure "sv") is not treated as a signing scheme.
        assert (
            canonicalize_url("https://x.com/d?sig=abc&keep=1")
            == "https://x.com/d?keep=1&sig=abc"
        )

    def test_keeps_meaningful_params_sorted(self):
        assert (
            canonicalize_url("https://x.com/search?q=test&page=2")
            == "https://x.com/search?page=2&q=test"
        )


class TestHtmlContentType:
    """Content-Type classification used to gate the HTML phishing model."""

    def test_html_types_are_html(self):
        assert is_html_content_type("text/html")
        assert is_html_content_type("text/html; charset=utf-8")
        assert is_html_content_type("application/xhtml+xml")

    def test_missing_content_type_is_lenient(self):
        # Servers that omit the header are still analysed rather than skipped.
        assert is_html_content_type(None)
        assert is_html_content_type("")

    def test_non_html_types_are_rejected(self):
        for ct in (
            "image/svg+xml",
            "image/png",
            "application/pdf",
            "application/zip",
            "application/octet-stream",
            "text/plain",
        ):
            assert not is_html_content_type(ct)
