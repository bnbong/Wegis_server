# --------------------------------------------------------------------------
# HTTP middleware test module (concurrency cap, rate limit, auth)
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

import src.api.middleware as mw
from src.server import app

client = TestClient(app)


def _settings(**overrides):
    base = dict(
        AUTH_MODE="off",
        api_tokens=set(),
        RATE_LIMIT_ENABLED=False,
        MAX_CONCURRENT_REQUESTS=32,
        RATE_LIMIT_CHECK_PER_MIN=120,
        RATE_LIMIT_BATCH_PER_MIN=12,
        REDIS_NAMESPACE="wegis",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestAuthMiddleware:
    def test_static_missing_token_rejected(self):
        with patch(
            "src.api.middleware.settings",
            _settings(AUTH_MODE="static", api_tokens={"secret"}),
        ):
            r = client.post("/analyze/check", json={"url": "https://x.com"})
        assert r.status_code == 401

    def test_static_wrong_token_rejected(self):
        with patch(
            "src.api.middleware.settings",
            _settings(AUTH_MODE="static", api_tokens={"secret"}),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "nope"},
            )
        assert r.status_code == 401

    def test_off_mode_allows_without_token(self):
        # AUTH_MODE=off -> no auth even if tokens exist
        from src.schemas.analyze import PhishingDetectionResponse

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze.return_value = PhishingDetectionResponse(
            result=False, confidence=0.0, source="whitelist", severity="allow"
        )
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="off", api_tokens={"secret"}),
            ),
            patch("src.api.routes.analyze.AnalyzerService", return_value=mock_analyzer),
            patch("src.api.deps.DBManager"),
        ):
            r = client.post("/analyze/check", json={"url": "https://x.com"})
        assert r.status_code == 200

    def test_registration_invalid_token_rejected(self):
        with (
            patch("src.api.middleware.settings", _settings(AUTH_MODE="registration")),
            patch(
                "src.api.middleware.is_token_valid",
                new=AsyncMock(return_value=False),
            ),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "bad"},
            )
        assert r.status_code == 401

    def test_health_is_not_protected(self):
        app.state.model = MagicMock()
        app.state.db_manager = MagicMock()
        try:
            with patch("src.api.middleware.settings", _settings(api_tokens={"secret"})):
                r = client.get("/health")
            assert r.status_code == 200
        finally:
            if hasattr(app.state, "model"):
                delattr(app.state, "model")
            if hasattr(app.state, "db_manager"):
                delattr(app.state, "db_manager")


class TestConcurrencyMiddleware:
    def test_over_capacity_returns_429(self):
        with patch("src.api.middleware.settings", _settings(MAX_CONCURRENT_REQUESTS=0)):
            r = client.post("/analyze/check", json={"url": "https://x.com"})
        assert r.status_code == 429


class TestRateLimitMiddleware:
    def test_over_limit_returns_429(self):
        mw._limiter_disabled_until = 0.0
        fake_redis = MagicMock()
        fake_redis.incr = AsyncMock(return_value=1)
        fake_redis.expire = AsyncMock()
        with (
            patch(
                "src.api.middleware.settings",
                _settings(RATE_LIMIT_ENABLED=True, RATE_LIMIT_CHECK_PER_MIN=0),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=fake_redis),
            ),
        ):
            r = client.post("/analyze/check", json={"url": "https://x.com"})
        assert r.status_code == 429

    def test_registration_valid_token_passes(self):
        from src.schemas.analyze import PhishingDetectionResponse

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze.return_value = PhishingDetectionResponse(
            result=False, confidence=0.0, source="whitelist", severity="allow"
        )
        with (
            patch("src.api.middleware.settings", _settings(AUTH_MODE="registration")),
            patch(
                "src.api.middleware.is_token_valid", new=AsyncMock(return_value=True)
            ),
            patch("src.api.routes.analyze.AnalyzerService", return_value=mock_analyzer),
            patch("src.api.deps.DBManager"),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "good"},
            )
        assert r.status_code == 200


def _fake_request(headers=None, host="1.2.3.4"):
    req = MagicMock()
    req.headers = headers or {}
    req.client = SimpleNamespace(host=host) if host else None
    return req


class TestClientKey:
    def test_token_keyed_by_hash_when_auth_active(self):
        from src.services.auth_tokens import hash_token

        req = _fake_request({"x-wegis-token": "secret"})
        with patch.object(mw.settings, "AUTH_MODE", "registration"):
            key = mw._client_key(req)
        assert key == f"tok:{hash_token('secret')}"
        assert "secret" not in key  # plaintext never in the key

    def test_token_ignored_in_off_mode(self):
        req = _fake_request({"x-wegis-token": "secret"}, host="9.9.9.9")
        with (
            patch.object(mw.settings, "AUTH_MODE", "off"),
            patch.object(mw.settings, "CLIENT_IP_HEADER", ""),
        ):
            key = mw._client_key(req)
        assert key == "ip:9.9.9.9"  # off mode -> IP, token ignored


class TestGetClientIp:
    def test_uses_socket_peer_by_default(self):
        from src.api.deps import get_client_ip, settings as deps_settings

        req = _fake_request(host="1.2.3.4")
        with patch.object(deps_settings, "CLIENT_IP_HEADER", ""):
            assert get_client_ip(req) == "1.2.3.4"

    def test_uses_trusted_header_when_configured(self):
        from src.api.deps import get_client_ip, settings as deps_settings

        req = _fake_request({"cf-connecting-ip": "5.6.7.8"}, host="10.0.0.1")
        with patch.object(deps_settings, "CLIENT_IP_HEADER", "cf-connecting-ip"):
            assert get_client_ip(req) == "5.6.7.8"
