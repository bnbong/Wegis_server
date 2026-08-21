# --------------------------------------------------------------------------
# Settings test module (auth mode promotion)
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import pytest

from src.core.config import Settings


class TestAuthModePromotion:
    def test_tokens_without_mode_promote_to_static(self):
        # The client contract documents WEGIS_API_TOKENS as the way to require a
        # token, so tokens alone must not leave /analyze/* unauthenticated.
        with pytest.warns(UserWarning, match="WEGIS_API_TOKENS"):
            s = Settings(WEGIS_API_TOKENS="tok-a,tok-b")
        assert s.AUTH_MODE == "static"
        assert s.api_tokens == {"tok-a", "tok-b"}

    def test_explicit_off_is_still_promoted(self):
        with pytest.warns(UserWarning, match="WEGIS_API_TOKENS"):
            s = Settings(AUTH_MODE="off", WEGIS_API_TOKENS="tok-a")
        assert s.AUTH_MODE == "static"

    def test_no_tokens_stays_off(self):
        s = Settings(AUTH_MODE="off", WEGIS_API_TOKENS="")
        assert s.AUTH_MODE == "off"

    def test_blank_tokens_stay_off(self):
        # Whitespace-only would promote into static mode with an empty
        # allowlist, i.e. lock every client out.
        s = Settings(AUTH_MODE="off", WEGIS_API_TOKENS="  ,  ")
        assert s.AUTH_MODE == "off"
        assert s.api_tokens == set()

    def test_registration_mode_is_not_overridden(self):
        s = Settings(AUTH_MODE="registration", WEGIS_API_TOKENS="tok-a")
        assert s.AUTH_MODE == "registration"

    def test_static_mode_is_unchanged(self):
        s = Settings(AUTH_MODE="static", WEGIS_API_TOKENS="tok-a")
        assert s.AUTH_MODE == "static"
