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
    def test_missing_token_rejected(self):
        with patch("src.api.middleware.settings", _settings(api_tokens={"secret"})):
            r = client.post("/analyze/check", json={"url": "https://x.com"})
        assert r.status_code == 401

    def test_wrong_token_rejected(self):
        with patch("src.api.middleware.settings", _settings(api_tokens={"secret"})):
            r = client.post(
                "/analyze/check",
                json={"url": "https://x.com"},
                headers={"X-Wegis-Token": "nope"},
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
