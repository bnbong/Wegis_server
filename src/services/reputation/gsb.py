# --------------------------------------------------------------------------
# Google Safe Browsing reputation provider (Lookup API v4)
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

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class GoogleSafeBrowsingProvider(ReputationProvider):
    name = "gsb"

    def __init__(self, api_key: str | None = None):
        self.api_key = (
            api_key if api_key is not None else settings.GOOGLE_SAFE_BROWSING_API_KEY
        )

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def check(self, url: str, client: httpx.AsyncClient) -> ReputationResult:
        payload = {
            "client": {"clientId": "wegis-server", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": _THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = await client.post(
            _ENDPOINT, params={"key": self.api_key}, json=payload
        )
        response.raise_for_status()
        data = response.json()

        matches = data.get("matches") or []
        if matches:
            reason_codes = sorted(
                {m.get("threatType", "") for m in matches if m.get("threatType")}
            )
            return ReputationResult(
                verdict=MALICIOUS,
                confidence=0.95,
                source=f"reputation:{self.name}",
                provider=self.name,
                reason_codes=reason_codes,
                raw=data,
            )

        return ReputationResult(
            verdict=CLEAN,
            confidence=0.0,
            source=f"reputation:{self.name}",
            provider=self.name,
        )
