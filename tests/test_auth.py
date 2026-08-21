# --------------------------------------------------------------------------
# Per-install auth test module (token validation + registration endpoint)
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from src.core.config import settings
from src.server import app
from src.services import auth_tokens

client = TestClient(app)


def _redis(get_value=None):
    redis = MagicMock()
    redis.get = AsyncMock(return_value=get_value)
    redis.setex = AsyncMock()
    return redis


class TestHashToken:
    def test_deterministic_sha256(self):
        assert auth_tokens.hash_token("abc") == auth_tokens.hash_token("abc")
        assert len(auth_tokens.hash_token("abc")) == 64
        assert auth_tokens.hash_token("abc") != "abc"


class TestBootstrapOk:
    def test_requires_configured_secret(self):
        with patch.object(settings, "REGISTRATION_BOOTSTRAP_SECRET", ""):
            assert auth_tokens.bootstrap_ok("anything") is False

    def test_matches_secret(self):
        with patch.object(settings, "REGISTRATION_BOOTSTRAP_SECRET", "s3cret"):
            assert auth_tokens.bootstrap_ok("s3cret") is True
            assert auth_tokens.bootstrap_ok("nope") is False
            assert auth_tokens.bootstrap_ok(None) is False

    def test_non_ascii_input_rejected(self):
        # compare_digest refuses non-ASCII str; header values can carry it, so a
        # bytes comparison must reject rather than raise.
        with patch.object(settings, "REGISTRATION_BOOTSTRAP_SECRET", "s3cret"):
            assert auth_tokens.bootstrap_ok("s3crét") is False


class TestIsTokenValid:
    @pytest.mark.asyncio
    async def test_empty_token_rejected(self):
        assert await auth_tokens.is_token_valid("") is False

    @pytest.mark.asyncio
    async def test_cache_active(self):
        with patch(
            "src.services.auth_tokens.get_redis",
            new=AsyncMock(return_value=_redis("active")),
        ):
            assert await auth_tokens.is_token_valid("tok") is True

    @pytest.mark.asyncio
    async def test_cache_revoked(self):
        with patch(
            "src.services.auth_tokens.get_redis",
            new=AsyncMock(return_value=_redis("revoked")),
        ):
            assert await auth_tokens.is_token_valid("tok") is False

    @pytest.mark.asyncio
    async def test_db_active_on_cache_miss(self):
        dbm = MagicMock()
        dbm.get_client_status = MagicMock(return_value="active")
        with (
            patch(
                "src.services.auth_tokens.get_redis",
                new=AsyncMock(return_value=_redis(None)),
            ),
            patch("src.services.auth_tokens.DBManager", return_value=dbm),
        ):
            assert await auth_tokens.is_token_valid("tok") is True

    @pytest.mark.asyncio
    async def test_db_unknown_rejected(self):
        dbm = MagicMock()
        dbm.get_client_status = MagicMock(return_value=None)
        with (
            patch(
                "src.services.auth_tokens.get_redis",
                new=AsyncMock(return_value=_redis(None)),
            ),
            patch("src.services.auth_tokens.DBManager", return_value=dbm),
        ):
            assert await auth_tokens.is_token_valid("tok") is False

    @pytest.mark.asyncio
    async def test_infra_error_fails_open(self):
        dbm = MagicMock()
        dbm.get_client_status = MagicMock(side_effect=RuntimeError("db down"))
        with (
            patch(
                "src.services.auth_tokens.get_redis",
                new=AsyncMock(return_value=_redis(None)),
            ),
            patch("src.services.auth_tokens.DBManager", return_value=dbm),
        ):
            assert await auth_tokens.is_token_valid("tok") is True


class TestRegisterEndpoint:
    def test_404_when_not_registration_mode(self):
        with patch.object(settings, "AUTH_MODE", "off"):
            r = client.post("/auth/register", json={})
        assert r.status_code == 404

    def test_invalid_bootstrap_rejected(self):
        with (
            patch.object(settings, "AUTH_MODE", "registration"),
            patch.object(settings, "REGISTRATION_BOOTSTRAP_SECRET", "s3cret"),
        ):
            r = client.post(
                "/auth/register", json={}, headers={"X-Wegis-Bootstrap": "wrong"}
            )
        assert r.status_code == 401

    def test_non_ascii_bootstrap_rejected(self):
        # A latin-1 header value must come back 401, not a 500 from the route.
        with (
            patch.object(settings, "AUTH_MODE", "registration"),
            patch.object(settings, "REGISTRATION_BOOTSTRAP_SECRET", "s3cret"),
        ):
            r = client.post(
                "/auth/register",
                json={},
                headers={"X-Wegis-Bootstrap": "s3crét".encode("latin-1")},
            )
        assert r.status_code == 401

    def test_register_success(self):
        with (
            patch.object(settings, "AUTH_MODE", "registration"),
            patch.object(settings, "REGISTRATION_BOOTSTRAP_SECRET", "s3cret"),
            patch(
                "src.api.routes.auth.registration_allowed",
                new=AsyncMock(return_value=True),
            ),
            patch(
                "src.api.routes.auth.register_client",
                new=AsyncMock(return_value=("tok-123", "iid-1")),
            ),
        ):
            r = client.post(
                "/auth/register",
                json={"ext_version": "1.0.0"},
                headers={"X-Wegis-Bootstrap": "s3cret"},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["token"] == "tok-123"
        assert body["install_id"] == "iid-1"

    def test_rate_limited(self):
        with (
            patch.object(settings, "AUTH_MODE", "registration"),
            patch.object(settings, "REGISTRATION_BOOTSTRAP_SECRET", "s3cret"),
            patch(
                "src.api.routes.auth.registration_allowed",
                new=AsyncMock(return_value=False),
            ),
        ):
            r = client.post(
                "/auth/register", json={}, headers={"X-Wegis-Bootstrap": "s3cret"}
            )
        assert r.status_code == 429
