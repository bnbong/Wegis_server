# --------------------------------------------------------------------------
# URL reputation stage test module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.reputation import (
    CLEAN,
    MALICIOUS,
    UNKNOWN,
    ReputationProvider,
    ReputationResult,
    ReputationService,
)
from src.services.reputation.gsb import GoogleSafeBrowsingProvider
from src.services.reputation.urlhaus import URLhausProvider
from src.services.reputation.virustotal import VirusTotalProvider


def _response(json_data: dict):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


def _client(json_data: dict):
    client = MagicMock()
    client.post = AsyncMock(return_value=_response(json_data))
    return client


def _vt_client(status_code: int, json_data: dict | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.raise_for_status = MagicMock()
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    client.post = AsyncMock(return_value=MagicMock())
    return client


def _vt_report(malicious: int, total: int = 70):
    undetected = max(0, total - malicious)
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "harmless": undetected,
                    "undetected": 0,
                    "timeout": 0,
                }
            }
        }
    }


class _FakeProvider(ReputationProvider):
    def __init__(self, name, result=None, exc=None, delay=0.0, applies=True):
        self.name = name
        self._result = result
        self._exc = exc
        self._delay = delay
        self._applies = applies
        self.calls = 0

    @property
    def enabled(self) -> bool:
        return True

    def applies_to(self, url):
        return self._applies(url) if callable(self._applies) else self._applies

    async def check(self, url, client):
        self.calls += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._exc:
            raise self._exc
        return self._result


def _result(verdict, provider="p", confidence=0.9, reasons=None):
    return ReputationResult(
        verdict=verdict,
        confidence=confidence,
        source=f"reputation:{provider}",
        provider=provider,
        reason_codes=reasons or [],
    )


class TestProviderEnabled:
    def test_gsb_enabled_only_with_key(self):
        assert GoogleSafeBrowsingProvider(api_key="k").enabled is True
        assert GoogleSafeBrowsingProvider(api_key="").enabled is False

    def test_urlhaus_enabled_only_with_key(self):
        assert URLhausProvider(auth_key="k").enabled is True
        assert URLhausProvider(auth_key="").enabled is False


class TestGoogleSafeBrowsingProvider:
    @pytest.mark.asyncio
    async def test_match_is_malicious(self):
        provider = GoogleSafeBrowsingProvider(api_key="k")
        client = _client(
            {
                "matches": [
                    {"threatType": "MALWARE"},
                    {"threatType": "SOCIAL_ENGINEERING"},
                ]
            }
        )
        result = await provider.check("https://evil.test/x", client)
        assert result.verdict == MALICIOUS
        assert result.confidence == 0.95
        assert result.reason_codes == ["MALWARE", "SOCIAL_ENGINEERING"]
        assert result.source == "reputation:gsb"

    @pytest.mark.asyncio
    async def test_no_match_is_clean(self):
        provider = GoogleSafeBrowsingProvider(api_key="k")
        result = await provider.check("https://safe.test/x", _client({}))
        assert result.verdict == CLEAN


class TestURLhausProvider:
    @pytest.mark.asyncio
    async def test_online_listing_is_malicious(self):
        provider = URLhausProvider(auth_key="k")
        client = _client(
            {"query_status": "ok", "url_status": "online", "threat": "malware_download"}
        )
        result = await provider.check("https://evil.test/payload.exe", client)
        assert result.verdict == MALICIOUS
        assert result.confidence == 0.9
        assert "malware_download" in result.reason_codes

    @pytest.mark.asyncio
    async def test_no_results_is_clean(self):
        provider = URLhausProvider(auth_key="k")
        result = await provider.check(
            "https://safe.test/x", _client({"query_status": "no_results"})
        )
        assert result.verdict == CLEAN


class TestMergePolicy:
    def test_any_malicious_wins_highest_confidence(self):
        merged = ReputationService._merge(
            [
                _result(CLEAN, "gsb", 0.0),
                _result(MALICIOUS, "urlhaus", 0.7, ["a"]),
                _result(MALICIOUS, "gsb", 0.95, ["b"]),
            ]
        )
        assert merged.verdict == MALICIOUS
        assert merged.confidence == 0.95
        assert merged.reason_codes == ["a", "b"]
        assert merged.provider == "gsb+urlhaus"

    def test_clean_when_no_malicious(self):
        assert ReputationService._merge([_result(CLEAN, "gsb", 0.0)]).verdict == CLEAN

    def test_unknown_when_empty(self):
        assert ReputationService._merge([]).verdict == UNKNOWN


class TestReputationService:
    @pytest.mark.asyncio
    async def test_cache_miss_queries_and_caches(self):
        provider = _FakeProvider("gsb", result=_result(MALICIOUS, "gsb", 0.95))
        service = ReputationService(providers=[provider])

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://evil.test/x")

        assert result.verdict == MALICIOUS
        assert provider.calls == 1
        redis.setex.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cache_hit_skips_providers(self):
        provider = _FakeProvider("gsb", result=_result(MALICIOUS, "gsb", 0.95))
        service = ReputationService(providers=[provider])

        redis = MagicMock()
        redis.get = AsyncMock(
            return_value=(
                '{"verdict":"malicious","confidence":0.95,'
                '"source":"reputation:gsb","provider":"gsb","reason_codes":["MALWARE"]}'
            )
        )
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://evil.test/x")

        assert result.verdict == MALICIOUS
        assert result.reason_codes == ["MALWARE"]
        assert provider.calls == 0
        redis.setex.assert_not_called()

    @pytest.mark.asyncio
    async def test_disabled_service_returns_none(self):
        provider = _FakeProvider("gsb", result=_result(MALICIOUS))
        service = ReputationService(providers=[provider])
        service._enabled = False
        assert await service.check("https://x.test") is None
        assert provider.calls == 0

    @pytest.mark.asyncio
    async def test_provider_error_is_fail_open_unknown(self):
        provider = _FakeProvider("gsb", exc=RuntimeError("boom"))
        service = ReputationService(providers=[provider])

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://x.test")

        assert result.verdict == UNKNOWN
        # unknown verdicts are not cached (retry next time)
        redis.setex.assert_not_called()

    @pytest.mark.asyncio
    async def test_provider_timeout_is_fail_open(self):
        slow = _FakeProvider("slow", result=_result(MALICIOUS), delay=0.2)
        service = ReputationService(providers=[slow])
        service.timeout = 0.01

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://x.test")

        assert result.verdict == UNKNOWN

    @pytest.mark.asyncio
    async def test_targeted_provider_skipped_for_non_matching_url(self):
        gsb = _FakeProvider("gsb", result=_result(CLEAN, "gsb", 0.0))
        vt = _FakeProvider(
            "vt",
            result=_result(MALICIOUS, "vt", 0.9),
            applies=lambda u: u.endswith(".exe"),
        )
        service = ReputationService(providers=[gsb, vt])

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://x.com/page.html")

        assert result.verdict == CLEAN
        assert gsb.calls == 1
        assert vt.calls == 0  # targeted provider gated out

    @pytest.mark.asyncio
    async def test_targeted_provider_runs_for_matching_url(self):
        gsb = _FakeProvider("gsb", result=_result(CLEAN, "gsb", 0.0))
        vt = _FakeProvider(
            "vt",
            result=_result(MALICIOUS, "vt", 0.9),
            applies=lambda u: u.endswith(".exe"),
        )
        service = ReputationService(providers=[gsb, vt])

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://x.com/installer.exe")

        assert result.verdict == MALICIOUS
        assert vt.calls == 1

    @pytest.mark.asyncio
    async def test_clean_not_cached_on_partial_outage(self):
        clean = _FakeProvider("gsb", result=_result(CLEAN, "gsb", 0.0))
        broken = _FakeProvider("urlhaus", exc=RuntimeError("timeout"))
        service = ReputationService(providers=[clean, broken])

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://x.test/partial")

        assert result.verdict == CLEAN
        # A provider failed, so the clean verdict must NOT be cached.
        redis.setex.assert_not_called()

    @pytest.mark.asyncio
    async def test_clean_cached_when_all_providers_respond(self):
        p1 = _FakeProvider("gsb", result=_result(CLEAN, "gsb", 0.0))
        p2 = _FakeProvider("urlhaus", result=_result(CLEAN, "urlhaus", 0.0))
        service = ReputationService(providers=[p1, p2])

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            result = await service.check("https://x.test/allclean")

        assert result.verdict == CLEAN
        redis.setex.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_concurrent_checks_are_coalesced(self):
        ReputationService._inflight.clear()
        provider = _FakeProvider("gsb", result=_result(CLEAN, "gsb", 0.0), delay=0.05)
        service = ReputationService(providers=[provider])

        redis = MagicMock()
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock()

        with patch(
            "src.services.reputation.service.get_redis",
            new=AsyncMock(return_value=redis),
        ):
            results = await asyncio.gather(
                service.check("https://x.test/dup"),
                service.check("https://x.test/dup"),
            )

        # Both concurrent misses coalesced into a single provider fan-out.
        assert provider.calls == 1
        assert all(r.verdict == CLEAN for r in results)


class TestVirusTotalProvider:
    def test_enabled_only_with_key(self):
        assert VirusTotalProvider(api_key="k").enabled is True
        assert VirusTotalProvider(api_key="").enabled is False

    def test_applies_only_to_high_risk_downloads(self):
        provider = VirusTotalProvider(api_key="k")
        assert provider.applies_to("https://x.com/setup.exe") is True
        assert provider.applies_to("https://x.com/archive.tar.gz") is True
        assert provider.applies_to("https://x.com/page.html") is False
        assert provider.applies_to("https://x.com/") is False
        assert provider.applies_to("https://example.com") is False

    @pytest.mark.asyncio
    async def test_report_above_threshold_is_malicious(self):
        provider = VirusTotalProvider(api_key="k", threshold=2)
        client = _vt_client(200, _vt_report(malicious=5, total=70))
        result = await provider.check("https://x.com/a.exe", client)
        assert result.verdict == MALICIOUS
        assert result.reason_codes == ["virustotal:5/70 engines"]

    @pytest.mark.asyncio
    async def test_report_below_threshold_is_clean(self):
        provider = VirusTotalProvider(api_key="k", threshold=2)
        client = _vt_client(200, _vt_report(malicious=1, total=70))
        result = await provider.check("https://x.com/a.exe", client)
        assert result.verdict == CLEAN

    @pytest.mark.asyncio
    async def test_not_found_is_unknown_without_submit(self):
        provider = VirusTotalProvider(api_key="k", submit_unknown=False)
        client = _vt_client(404)
        result = await provider.check("https://x.com/a.exe", client)
        assert result.verdict == UNKNOWN
        client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_not_found_seeds_scan_when_enabled(self):
        provider = VirusTotalProvider(api_key="k", submit_unknown=True)
        client = _vt_client(404)
        result = await provider.check("https://x.com/a.exe", client)
        assert result.verdict == UNKNOWN
        client.post.assert_awaited_once()
