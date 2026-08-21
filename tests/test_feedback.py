# --------------------------------------------------------------------------
# Feedback endpoint test module (POST /feedback)
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import src.api.middleware as mw
from src.server import app

client = TestClient(app)

# The extension id differs per build, so CORS matches it by regex.
EXTENSION_ORIGIN = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef"


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


def _fake_redis(incr_value=1, decr_value=0):
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.incr = AsyncMock(return_value=incr_value)
    redis.decr = AsyncMock(return_value=decr_value)
    redis.expire = AsyncMock()
    return redis


def _db(save_side_effect=None):
    """DBManager stand-in; save_feedback is the only method the route touches."""
    db_manager = MagicMock()
    db_manager.save_feedback = MagicMock(side_effect=save_side_effect)
    return db_manager


@pytest.fixture(autouse=True)
def _reset_breakers():
    """The limiters keep process-global circuit breakers; a fail-open in one
    test would otherwise silently disable the limiter in the next."""
    mw._limiter_disabled_until = 0.0
    mw._authfail_disabled_until = 0.0
    yield


class TestFeedbackAccepted:
    def test_report_is_queued_with_normalized_url(self):
        db_manager = _db()
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post(
                "/feedback",
                json={
                    "url": "  HTTP://WWW.Example.com/Path/?b=2&a=1  ",
                    "reported_verdict": "phishing",
                    "user_label": "false_positive",
                    "context": "link",
                    "ext_version": "2.0.1",
                },
            )

        assert response.status_code == 202
        body = response.json()
        assert body["message"] == "SUCCESS"
        assert body["data"]["accepted"] is True
        # Never auto-applied to the blacklist/whitelist: reports queue for review.
        assert body["data"]["review_status"] == "pending"

        db_manager.save_feedback.assert_called_once()
        kwargs = db_manager.save_feedback.call_args.kwargs
        # Canonicalized the same way the analysis path keys its cache.
        assert kwargs["url"] == "http://example.com/Path?a=1&b=2"
        assert kwargs["reported_verdict"] == "phishing"
        assert kwargs["user_label"] == "false_positive"
        assert kwargs["context"] == "link"
        assert kwargs["ext_version"] == "2.0.1"

    def test_client_identifier_is_hashed(self):
        db_manager = _db()
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post(
                "/feedback",
                json={"url": "https://example.com"},
                headers={"X-Wegis-Token": "s3cret-token"},
            )

        assert response.status_code == 202
        client_id_hash = db_manager.save_feedback.call_args.kwargs["client_id_hash"]
        assert len(client_id_hash) == 64  # sha256 hex
        assert "s3cret-token" not in client_id_hash

    def test_url_only_report_is_accepted(self):
        db_manager = _db()
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post("/feedback", json={"url": "example.com/login"})

        assert response.status_code == 202
        kwargs = db_manager.save_feedback.call_args.kwargs
        # Scheme-less input is assumed https, same as the analysis contract.
        assert kwargs["url"] == "https://example.com/login"
        assert kwargs["reported_verdict"] is None
        assert kwargs["user_label"] is None
        assert kwargs["context"] is None
        assert kwargs["ext_version"] is None


class TestFeedbackValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "",
            "   ",
            "javascript:alert(1)",
            "data:text/html,<h1>x</h1>",
            "ftp://files.example.com/x",
            "mailto:someone@example.com",
            "https://example.com:99999/",  # unparseable port
            "http://",  # no host
            "https://example.com/" + "a" * 3000,  # over the length cap
        ],
    )
    def test_bad_url_rejected(self, url):
        db_manager = _db()
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post("/feedback", json={"url": url})

        assert response.status_code == 422
        db_manager.save_feedback.assert_not_called()

    def test_missing_url_rejected(self):
        db_manager = _db()
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post("/feedback", json={"ext_version": "2.0.1"})

        assert response.status_code == 422
        db_manager.save_feedback.assert_not_called()

    def test_unknown_enum_values_are_dropped_not_rejected(self):
        # A client shipping a value this server does not know yet must still get
        # its report stored, minus the unknown field.
        db_manager = _db()
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post(
                "/feedback",
                json={
                    "url": "https://example.com",
                    "reported_verdict": "definitely_evil",
                    "user_label": 7,
                    "context": "popup",
                    "ext_version": "v" * 100,
                },
            )

        assert response.status_code == 202
        kwargs = db_manager.save_feedback.call_args.kwargs
        assert kwargs["reported_verdict"] is None
        assert kwargs["user_label"] is None
        assert kwargs["context"] is None
        # ext_version is observability only: truncated, never a reason to fail.
        assert kwargs["ext_version"] == "v" * 32

    def test_known_values_are_case_normalized(self):
        db_manager = _db()
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post(
                "/feedback",
                json={
                    "url": "https://example.com",
                    "reported_verdict": "PHISHING",
                    "user_label": "False_Negative",
                    "context": " navigation ",
                },
            )

        assert response.status_code == 202
        kwargs = db_manager.save_feedback.call_args.kwargs
        assert kwargs["reported_verdict"] == "phishing"
        assert kwargs["user_label"] == "false_negative"
        assert kwargs["context"] == "navigation"


class TestFeedbackStorageFailure:
    def test_storage_failure_is_a_deliberate_5xx(self):
        # The client is fire-and-forget and only checks for a 2xx, so answering
        # 202 on a failed write would claim a report we never stored.
        db_manager = _db(save_side_effect=RuntimeError("db down"))
        with patch("src.api.deps.DBManager", return_value=db_manager):
            response = client.post("/feedback", json={"url": "https://example.com"})

        assert response.status_code == 503
        # A rendered JSON body, not a propagated stack trace.
        assert response.json()["detail"] == "Feedback storage unavailable"


class TestFeedbackAuth:
    def test_missing_token_rejected_in_static_mode(self):
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
            response = client.post("/feedback", json={"url": "https://example.com"})

        assert response.status_code == 401

    def test_correct_token_accepted_in_static_mode(self):
        db_manager = _db()
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
            patch("src.api.deps.DBManager", return_value=db_manager),
        ):
            response = client.post(
                "/feedback",
                json={"url": "https://example.com"},
                headers={"X-Wegis-Token": "secret"},
            )

        assert response.status_code == 202
        db_manager.save_feedback.assert_called_once()


class TestFeedbackRateLimit:
    def test_over_limit_returns_429(self):
        db_manager = _db()
        with (
            patch(
                "src.api.middleware.settings",
                _settings(
                    RATE_LIMIT_ENABLED=True,
                    # Deliberately generous elsewhere: only the /feedback limit
                    # can produce this 429, which pins the limit selection.
                    RATE_LIMIT_FEEDBACK_PER_MIN=0,
                    RATE_LIMIT_CHECK_PER_MIN=120,
                ),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
            patch("src.api.deps.DBManager", return_value=db_manager),
        ):
            response = client.post("/feedback", json={"url": "https://example.com"})

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "60"
        db_manager.save_feedback.assert_not_called()

    def test_within_limit_passes(self):
        db_manager = _db()
        with (
            patch(
                "src.api.middleware.settings",
                _settings(RATE_LIMIT_ENABLED=True, RATE_LIMIT_FEEDBACK_PER_MIN=30),
            ),
            patch(
                "src.api.middleware.get_redis",
                new=AsyncMock(return_value=_fake_redis()),
            ),
            patch("src.api.deps.DBManager", return_value=db_manager),
        ):
            response = client.post("/feedback", json={"url": "https://example.com"})

        assert response.status_code == 202


class TestFeedbackCORS:
    """Guards the middleware ordering: CORS must sit OUTSIDE auth.

    Registered the other way round, a preflight (which carries no token) is
    answered 401 and also charged to the caller's auth-failure budget.
    """

    def test_preflight_is_not_blocked_by_auth(self):
        redis = _fake_redis()
        with (
            patch(
                "src.api.middleware.settings",
                _settings(AUTH_MODE="static", api_tokens={"secret"}),
            ),
            patch("src.api.middleware.get_redis", new=AsyncMock(return_value=redis)),
        ):
            response = client.options(
                "/feedback",
                headers={
                    "Origin": EXTENSION_ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type, x-wegis-token",
                },
            )

        assert response.status_code in (200, 204)
        assert response.headers["access-control-allow-origin"] == EXTENSION_ORIGIN
        allow_methods = response.headers["access-control-allow-methods"].upper()
        assert "POST" in allow_methods
        allow_headers = response.headers["access-control-allow-headers"].lower()
        assert "content-type" in allow_headers
        assert "x-wegis-token" in allow_headers
        assert "accept" in allow_headers
        # Never reached auth, so it cost the caller nothing from its budget.
        redis.incr.assert_not_awaited()

    def test_rejected_request_still_carries_cors_headers(self):
        # Without CORS on the outside the extension sees an opaque network
        # error instead of the 401 it needs to act on.
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
            response = client.post(
                "/feedback",
                json={"url": "https://example.com"},
                headers={"Origin": EXTENSION_ORIGIN},
            )

        assert response.status_code == 401
        assert response.headers["access-control-allow-origin"] == EXTENSION_ORIGIN
