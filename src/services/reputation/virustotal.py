# --------------------------------------------------------------------------
# VirusTotal reputation provider (Phase 2 — download scanning)
#
# Delegates scanning to VirusTotal by URL (the server never downloads or hashes
# the file itself). Lookup-first to conserve quota; only runs for high-risk
# download URLs. Async submit→poll is approximated by seeding a scan on a cache
# miss (optional) and reading the result on subsequent requests.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import base64
import logging
from urllib.parse import urlsplit

import httpx

from src.core.config import settings
from src.services.reputation.base import (
    CLEAN,
    MALICIOUS,
    UNKNOWN,
    ReputationProvider,
    ReputationResult,
)

logger = logging.getLogger("main")

_BASE = "https://www.virustotal.com/api/v3"

# Extensions that commonly deliver malware. The reputation stage runs before the
# fetch, so gating is by URL extension (Content-Type is not yet known).
HIGH_RISK_DOWNLOAD_EXTENSIONS = frozenset(
    {
        "exe",
        "msi",
        "msix",
        "scr",
        "com",
        "pif",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "js",
        "jar",
        "apk",
        "dmg",
        "pkg",
        "deb",
        "rpm",
        "appimage",
        "run",
        "sh",
        "zip",
        "rar",
        "7z",
        "gz",
        "tar",
        "iso",
        "img",
        "cab",
        "ace",
        "lnk",
        "hta",
        "dll",
        "bin",
    }
)


def _url_extension(url: str) -> str:
    path = urlsplit(url).path
    _, _, ext = path.rpartition(".")
    if "/" in ext or not ext:
        return ""
    return ext.lower()


class VirusTotalProvider(ReputationProvider):
    name = "virustotal"

    def __init__(
        self,
        api_key: str | None = None,
        threshold: int | None = None,
        submit_unknown: bool | None = None,
    ):
        self.api_key = api_key if api_key is not None else settings.VIRUSTOTAL_API_KEY
        self.threshold = (
            threshold
            if threshold is not None
            else settings.VIRUSTOTAL_MALICIOUS_THRESHOLD
        )
        self.submit_unknown = (
            submit_unknown
            if submit_unknown is not None
            else settings.VIRUSTOTAL_SUBMIT_UNKNOWN
        )

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def applies_to(self, url: str) -> bool:
        return _url_extension(url) in HIGH_RISK_DOWNLOAD_EXTENSIONS

    @staticmethod
    def _url_id(url: str) -> str:
        # VT v3 URL identifier: unpadded base64url of the URL.
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def _clean(self) -> ReputationResult:
        return ReputationResult(
            verdict=CLEAN,
            confidence=0.0,
            source=f"reputation:{self.name}",
            provider=self.name,
        )

    def _unknown(self) -> ReputationResult:
        return ReputationResult(
            verdict=UNKNOWN,
            confidence=0.0,
            source=f"reputation:{self.name}",
            provider=self.name,
        )

    async def check(self, url: str, client: httpx.AsyncClient) -> ReputationResult:
        headers = {"x-apikey": self.api_key}
        response = await client.get(
            f"{_BASE}/urls/{self._url_id(url)}", headers=headers
        )

        if response.status_code == 404:
            # No existing report. Optionally seed a scan for next time; this
            # request stays unknown (fail-open) rather than blocking on analysis.
            if self.submit_unknown:
                await self._submit(url, client, headers)
            return self._unknown()

        response.raise_for_status()
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        total = sum(int(v) for v in stats.values()) or 1

        if malicious >= self.threshold:
            confidence = round(min(0.99, 0.7 + 0.03 * malicious), 2)
            return ReputationResult(
                verdict=MALICIOUS,
                confidence=confidence,
                source=f"reputation:{self.name}",
                provider=self.name,
                reason_codes=[f"virustotal:{malicious}/{total} engines"],
                raw=stats,
            )

        return self._clean()

    async def _submit(self, url: str, client: httpx.AsyncClient, headers: dict) -> None:
        try:
            await client.post(f"{_BASE}/urls", data={"url": url}, headers=headers)
            logger.info("Submitted %s to VirusTotal for scanning", url)
        except Exception as exc:  # best-effort seed; never affects the verdict
            logger.warning("VirusTotal submit failed for %s: %s", url, exc)
