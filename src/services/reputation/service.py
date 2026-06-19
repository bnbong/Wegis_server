# --------------------------------------------------------------------------
# URL reputation orchestration service
#
# Calls the configured providers in parallel (per-provider timeout), merges the
# verdicts with an OR policy, and caches the merged result in Redis. Every
# external dependency (providers, Redis) is fail-open: any error degrades to
# "unknown" so the reputation feed can never block the analysis pipeline.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio
import json
import logging
from typing import Optional

import httpx

from src.core.config import settings
from src.clients.redis import get_redis
from src.services.url_utils import canonicalize_url
from src.services.reputation.base import (
    CLEAN,
    MALICIOUS,
    UNKNOWN,
    ReputationProvider,
    ReputationResult,
)
from src.services.reputation.gsb import GoogleSafeBrowsingProvider
from src.services.reputation.urlhaus import URLhausProvider
from src.services.reputation.virustotal import VirusTotalProvider

logger = logging.getLogger("main")


class ReputationService:
    # Shared across instances so concurrency/coalescing is global (the analyzer
    # may construct more than one ReputationService).
    _semaphore = asyncio.Semaphore(settings.REPUTATION_MAX_CONCURRENCY)
    _inflight: dict[str, "asyncio.Task[ReputationResult]"] = {}
    _inflight_lock = asyncio.Lock()

    def __init__(self, providers: Optional[list[ReputationProvider]] = None):
        self._enabled = settings.REPUTATION_ENABLED
        self.timeout = settings.REPUTATION_TIMEOUT
        if providers is None:
            providers = [
                GoogleSafeBrowsingProvider(),
                URLhausProvider(),
                VirusTotalProvider(),
            ]
        # Only keep providers that are actually configured (e.g. API key present).
        self.providers = [p for p in providers if p.enabled]
        if self._enabled and not self.providers:
            logger.info(
                "Reputation enabled but no providers configured; stage is a no-op"
            )

    @property
    def enabled(self) -> bool:
        return self._enabled and bool(self.providers)

    def _cache_key(self, url: str) -> str:
        return f"{settings.REDIS_NAMESPACE}:reputation:{canonicalize_url(url)}"

    async def check(self, url: str) -> Optional[ReputationResult]:
        """Return a merged reputation result, or None when the stage is disabled."""
        if not self.enabled:
            return None

        cached = await self._get_cached(url)
        if cached is not None:
            return cached

        # Coalesce concurrent misses for the same canonical URL so a batch (or
        # duplicate concurrent requests) hits the external APIs only once.
        key = self._cache_key(url)
        async with self._inflight_lock:
            task = self._inflight.get(key)
            if task is None:
                task = asyncio.create_task(self._check_miss(url, key))
                self._inflight[key] = task
        return await asyncio.shield(task)

    async def _check_miss(self, url: str, key: str) -> ReputationResult:
        try:
            merged, complete = await self._query_providers(url)

            # Caching policy:
            #  - MALICIOUS is decisive -> always cache.
            #  - CLEAN is only cached when EVERY applicable provider responded. If
            #    a provider timed out/errored, a different one might have flagged
            #    it, so we must not lock in "clean" for the whole TTL.
            #  - UNKNOWN is never cached (retry next time).
            if merged.verdict == MALICIOUS or (merged.verdict == CLEAN and complete):
                await self._set_cached(url, merged)

            return merged
        finally:
            async with self._inflight_lock:
                self._inflight.pop(key, None)

    async def _query_providers(self, url: str) -> tuple[ReputationResult, bool]:
        """Return (merged result, complete) where ``complete`` is True only when
        every applicable provider responded successfully."""
        # Per-URL provider gate: targeted providers (e.g. VirusTotal) only run for
        # the URLs they apply to (high-risk downloads), conserving quota.
        applicable = [p for p in self.providers if p.applies_to(url)]
        if not applicable:
            return self._merge([]), True

        try:
            # Bound concurrent external fan-outs to protect provider quotas.
            async with self._semaphore:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    results = await asyncio.gather(
                        *(self._safe_check(p, url, client) for p in applicable)
                    )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Reputation provider fan-out failed for %s: %s", url, exc)
            results = [None] * len(applicable)

        successful = [r for r in results if r is not None]
        complete = len(successful) == len(applicable)
        return self._merge(successful), complete

    async def _safe_check(
        self, provider: ReputationProvider, url: str, client: httpx.AsyncClient
    ) -> Optional[ReputationResult]:
        try:
            return await asyncio.wait_for(
                provider.check(url, client), timeout=self.timeout
            )
        except Exception as exc:
            # fail-open: a slow/broken provider simply contributes nothing.
            logger.warning(
                "Reputation provider %s failed for %s: %s", provider.name, url, exc
            )
            return None

    @staticmethod
    def _merge(results: list[ReputationResult]) -> ReputationResult:
        # OR policy: any malicious -> malicious (highest-confidence wins, reasons
        # and providers combined).
        malicious = [r for r in results if r.verdict == MALICIOUS]
        if malicious:
            best = max(malicious, key=lambda r: r.confidence)
            reason_codes = sorted({c for r in malicious for c in r.reason_codes})
            providers = "+".join(sorted({r.provider for r in malicious}))
            return ReputationResult(
                verdict=MALICIOUS,
                confidence=best.confidence,
                source=f"reputation:{providers}",
                provider=providers,
                reason_codes=reason_codes,
                raw=best.raw,
            )

        if any(r.verdict == CLEAN for r in results):
            return ReputationResult(
                verdict=CLEAN,
                confidence=0.0,
                source="reputation",
                provider="reputation",
            )

        return ReputationResult(
            verdict=UNKNOWN, confidence=0.0, source="reputation", provider="reputation"
        )

    async def _get_cached(self, url: str) -> Optional[ReputationResult]:
        try:
            redis_client = await get_redis()
            raw = await redis_client.get(self._cache_key(url))  # type: ignore
            if not raw:
                return None
            data = json.loads(raw)
            return ReputationResult(
                verdict=data["verdict"],
                confidence=data.get("confidence", 0.0),
                source=data.get("source", "reputation"),
                provider=data.get("provider", "reputation"),
                reason_codes=data.get("reason_codes", []),
            )
        except Exception as exc:  # fail-open on cache read
            logger.warning("Reputation cache read failed for %s: %s", url, exc)
            return None

    async def _set_cached(self, url: str, result: ReputationResult) -> None:
        ttl = (
            settings.REPUTATION_CACHE_TTL_MALICIOUS
            if result.verdict == MALICIOUS
            else settings.REPUTATION_CACHE_TTL_CLEAN
        )
        payload = json.dumps(
            {
                "verdict": result.verdict,
                "confidence": result.confidence,
                "source": result.source,
                "provider": result.provider,
                "reason_codes": result.reason_codes,
            }
        )
        try:
            redis_client = await get_redis()
            await redis_client.setex(self._cache_key(url), ttl, payload)  # type: ignore
        except Exception as exc:  # fail-open on cache write
            logger.warning("Reputation cache write failed for %s: %s", url, exc)
