# --------------------------------------------------------------------------
# URLhaus (abuse.ch) reputation provider
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import httpx

from src.core.config import settings
from src.services.reputation.base import (
    CLEAN,
    MALICIOUS,
    ReputationProvider,
    ReputationResult,
)

_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausProvider(ReputationProvider):
    name = "urlhaus"

    def __init__(self, auth_key: str | None = None):
        self.auth_key = auth_key if auth_key is not None else settings.URLHAUS_AUTH_KEY

    @property
    def enabled(self) -> bool:
        # abuse.ch requires an Auth-Key for the URLhaus API.
        return bool(self.auth_key)

    async def check(self, url: str, client: httpx.AsyncClient) -> ReputationResult:
        response = await client.post(
            _ENDPOINT,
            data={"url": url},
            headers={"Auth-Key": self.auth_key},
        )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") == "ok":
            url_status = data.get("url_status")  # "online" | "offline" | ""
            threat = data.get("threat")
            # An actively-online malicious URL is a stronger signal than an
            # offline (de-listed) one.
            confidence = 0.9 if url_status == "online" else 0.7
            reason_codes = [c for c in (threat, url_status) if c]
            return ReputationResult(
                verdict=MALICIOUS,
                confidence=confidence,
                source=f"reputation:{self.name}",
                provider=self.name,
                reason_codes=reason_codes,
                raw=data,
            )

        # "no_results" / "invalid_url" / etc. -> not listed.
        return ReputationResult(
            verdict=CLEAN,
            confidence=0.0,
            source=f"reputation:{self.name}",
            provider=self.name,
        )
