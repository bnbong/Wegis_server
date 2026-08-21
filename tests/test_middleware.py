# --------------------------------------------------------------------------
# HTTP middleware test module (concurrency cap, rate limit, auth)
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
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
        RATE_LIMIT_FEEDBACK_PER_MIN=30,
        AUTH_FAIL_LIMIT_PER_MIN=30,
        REDIS_NAMESPACE="wegis",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _fake_redis(get_value=None, incr_value=1, decr_value=0):
    redis = MagicMock()
    redis.get = AsyncMock(return_value=get_value)
    redis.incr = AsyncMock(return_value=incr_value)
    redis.decr = AsyncMock(return_value=decr_value)
    redis.expire = AsyncMock()
    return redis


class _CountingRedis:
    """In-memory stand-in for the GET/INCR/DECR/EXPIRE the limiters use.

    Keys are stripped of their trailing time window so a minute rollover in the
    middle of a test cannot reset the counter. Every call yields to the event
    loop first, modelling a network round trip: concurrent requests then really
    do interleave, while each read-modify-write stays atomic like Redis's.
    """

    def __init__(self):
        self.values: dict[str, int] = {}

    @staticmethod
    def _norm(key: str) -> str:
        return key.rsplit(":", 1)[0]

    async def get(self, key):
        await asyncio.sleep(0)
        value = self.values.get(self._norm(key))
        return None if value is None else str(value)

    async def incr(self, key):
        await asyncio.sleep(0)
        self.values[self._norm(key)] = self.values.get(self._norm(key), 0) + 1
        return self.values[self._norm(key)]

    async def decr(self, key):
        await asyncio.sleep(0)
        self.values[self._norm(key)] = self.values.get(self._norm(key), 0) - 1
        return self.values[self._norm(key)]

    async def expire(self, key, ttl):
        await asyncio.sleep(0)
        return True


@pytest.fixture(autouse=True)
def _reset_breakers():
    """Both limiters keep process-global circuit breakers; a fail-open in one
    test would otherwise silently disable the limiter in the next."""
    mw._limiter_disabled_until = 0.0
    mw._authfail_disabled_until = 0.0
    yield


def _ok_analyzer():
    from src.schemas.analyze import PhishingDetectionResponse

    analyzer = AsyncMock()
    analyzer.analyze.return_value = PhishingDetectionResponse(
        result=False, confidence=0.0, source="whitelist", severity="allow"
    )
    return analyzer


class TestAuthMiddleware:
    def test_static_missing_token_rejected(self):
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
        ):
            r = client.post("/analyze/check", json={"url": "https://x.com"})
        assert r.status_code == 401

    def test_static_wrong_token_rejected(self):
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "nope"},
            )
        assert r.status_code == 401

    def test_static_correct_token_passes(self):
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret", "other"}),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
            patch(
                "src.api.routes.analyze.AnalyzerService", return_value=_ok_analyzer()
            ),
            patch("src.api.deps.DBManager"),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "secret"},
            )
        assert r.status_code == 200

    def test_static_non_ascii_token_rejected(self):
        # hmac.compare_digest refuses non-ASCII str; a latin-1 header value must
        # come back 401, not a 500 from the middleware.
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "sécret".encode("latin-1")},
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
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
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


class TestAuthFailureLimiter:
    def test_failures_beyond_limit_return_429(self):
        redis = _CountingRedis()
        with (
            patch(
                "src.api.middleware.settings",
                _settings(
                    AUTH_MODE="static",
                    api_tokens={"secret"},
                    AUTH_FAIL_LIMIT_PER_MIN=3,
                ),
            ),
            patch("src.api.middleware.get_redis", new=AsyncMock(return_value=redis)),
        ):
            codes = [
                client.post(
                    "/analyze/check",
                    json={"url": "https://x.com"},
                    headers={"X-Wegis-Token": "nope"},
                ).status_code
                for _ in range(5)
            ]
        assert codes == [401, 401, 401, 429, 429]

    def test_failure_is_charged_with_expiry(self):
        redis = _fake_redis(incr_value=1)
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch("src.api.middleware.get_redis", new=AsyncMock(return_value=redis)),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "nope"},
            )
        assert r.status_code == 401
        redis.incr.assert_awaited_once()  # charged up front
        key = redis.incr.await_args.args[0]
        assert key.startswith("wegis:authfail:")
        redis.expire.assert_awaited_once()  # TTL set on the first charge only
        redis.decr.assert_not_awaited()  # a failure keeps its charge

    def test_over_limit_skips_token_validation(self):
        # registration mode: the DB/Redis lookup must not run once the IP is
        # over budget, otherwise brute-force still costs a lookup per attempt.
        checker = AsyncMock(return_value=False)
        redis = _fake_redis(incr_value=31)  # charge lands above the limit of 30
        with (
            patch("src.api.middleware.settings", _settings(AUTH_MODE="registration")),
            patch("src.api.middleware.get_redis", new=AsyncMock(return_value=redis)),
            patch("src.api.middleware.is_token_valid", new=checker),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "bad"},
            )
        assert r.status_code == 429
        assert r.headers["Retry-After"] == "60"
        checker.assert_not_awaited()

    def test_successful_auth_is_refunded(self):
        redis = _fake_redis(incr_value=1, decr_value=0)
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch("src.api.middleware.get_redis", new=AsyncMock(return_value=redis)),
            patch(
                "src.api.routes.analyze.AnalyzerService", return_value=_ok_analyzer()
            ),
            patch("src.api.deps.DBManager"),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "secret"},
            )
        assert r.status_code == 200
        redis.incr.assert_awaited_once()  # charged...
        redis.decr.assert_awaited_once()  # ...then handed straight back

    def test_successes_do_not_consume_the_failure_budget(self):
        redis = _CountingRedis()
        settings_patch = patch(
            "src.api.middleware.settings",
            _settings(
                AUTH_MODE="static", api_tokens={"secret"}, AUTH_FAIL_LIMIT_PER_MIN=3
            ),
        )
        redis_patch = patch(
            "src.api.middleware.get_redis", new=AsyncMock(return_value=redis)
        )
        with (
            settings_patch,
            redis_patch,
            patch(
                "src.api.routes.analyze.AnalyzerService", return_value=_ok_analyzer()
            ),
            patch("src.api.deps.DBManager"),
        ):
            for _ in range(5):
                ok = client.post(
                    "/analyze/check",
                    json={"url": "https://x.com"},
                    headers={"X-Wegis-Token": "secret"},
                )
                assert ok.status_code == 200
        assert not any(redis.values.values())  # budget back to zero

        # The full failure budget must still be there after those successes.
        with settings_patch, redis_patch:
            codes = [
                client.post(
                    "/analyze/check",
                    json={"url": "https://x.com"},
                    headers={"X-Wegis-Token": "nope"},
                ).status_code
                for _ in range(4)
            ]
        assert codes == [401, 401, 401, 429]

    @pytest.mark.asyncio
    async def test_concurrent_failures_bound_token_validations(self):
        # The charge must be taken atomically BEFORE validation: with a
        # read-then-check limiter every request in a simultaneous burst reads the
        # same low count, passes, and hits is_token_valid() together.
        redis = _CountingRedis()
        checker = AsyncMock(return_value=False)
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="registration", AUTH_FAIL_LIMIT_PER_MIN=3),
            ),
            patch("src.api.middleware.get_redis", new=AsyncMock(return_value=redis)),
            patch("src.api.middleware.is_token_valid", new=checker),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as ac:
                responses = await asyncio.gather(
                    *[
                        ac.post(
                            "/analyze/check",
                            json={"url": "https://x.com"},
                            headers={"X-Wegis-Token": "bad"},
                        )
                        for _ in range(8)
                    ]
                )
        assert sorted(r.status_code for r in responses) == [401] * 3 + [429] * 5
        assert checker.await_count == 3  # validation calls bounded by the limit

    def test_redis_failure_fails_open(self):
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(side_effect=RuntimeError("redis down")),
            ),
        ):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "nope"},
            )
        # Limiter unavailable -> still authenticate, just without the counter.
        assert r.status_code == 401
        assert mw._authfail_disabled_until > 0.0  # breaker opened

    def test_off_mode_does_not_touch_limiter(self):
        redis = _fake_redis()
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="off", api_tokens={"secret"}),
            ),
            patch("src.api.middleware.get_redis", new=AsyncMock(return_value=redis)),
            patch(
                "src.api.routes.analyze.AnalyzerService", return_value=_ok_analyzer()
            ),
            patch("src.api.deps.DBManager"),
        ):
            r = client.post("/analyze/check", json={"url": "https://x.com"})
        assert r.status_code == 200
        redis.incr.assert_not_awaited()


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
        with (
            patch("src.api.middleware.settings", _settings(AUTH_MODE="registration")),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
            patch(
                "src.api.middleware.is_token_valid", new=AsyncMock(return_value=True)
            ),
            patch(
                "src.api.routes.analyze.AnalyzerService", return_value=_ok_analyzer()
            ),
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
