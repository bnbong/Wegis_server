# --------------------------------------------------------------------------
# Analyzer service module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
import asyncio

from fastapi import Request
from typing import Awaitable, Callable, Optional

from src.database import DBManager
from src.exceptions import BackendExceptions
from src.services.domain_checker import DomainChecker
from src.schemas.analyze import PhishingDetectionResponse
from src.clients.redis import get_redis
from src.core.config import settings
from src.services.fetchers.hybrid_fetcher import HybridFetcher
from src.services.fetchers.http_fetcher import is_html_content_type
from src.services.net_guard import SSRFBlockedError
from src.services.performance import StageTimer, build_perf_record, log_perf_record
from src.services.reputation import ReputationService
from src.services.url_utils import canonicalize_url

logger = logging.getLogger("main")


class AnalyzerService:
    _inflight_lock = asyncio.Lock()
    _inflight_tasks: dict[str, asyncio.Task[PhishingDetectionResponse]] = {}
    # Background model analysis for cache-miss links (design 01, opt-in).
    _bg_tasks: set[asyncio.Task] = set()
    _bg_inflight_keys: set[str] = set()
    _bg_semaphore = asyncio.Semaphore(settings.LINK_BG_CONCURRENCY)

    def __init__(self):
        self.fetcher = HybridFetcher()
        self.reputation_service = ReputationService()
        self.browser_semaphore = asyncio.Semaphore(settings.MAX_BROWSER_CONCURRENCY)
        self.infer_semaphore = asyncio.Semaphore(settings.MAX_INFER_CONCURRENCY)

    # ----- response / severity helpers (design 02) -----

    @staticmethod
    def _model_severity(confidence: float, context: str) -> str:
        """Map a model confidence (= P(phishing)) to a severity tier.

        A ``link`` is never hard-blocked by the model — only warned — because a
        link-badge false positive is low-actionability.
        """
        if context == "link":
            return "warn" if confidence >= settings.MODEL_BLOCK_THRESHOLD else "allow"
        if confidence >= settings.MODEL_BLOCK_THRESHOLD:
            return "block"
        if confidence >= settings.MODEL_WARN_THRESHOLD:
            return "warn"
        return "allow"

    @staticmethod
    def _build_response(
        *,
        url: str,
        source: str,
        confidence: float,
        fetch_mode: str | None,
        severity: str,
        status: str = "final",
        reason_codes: Optional[list[str]] = None,
    ) -> PhishingDetectionResponse:
        return PhishingDetectionResponse.model_validate(
            {
                "url": url,
                "result": severity == "block",
                "confidence": confidence,
                "source": source,
                "fetch_mode": fetch_mode,
                "severity": severity,
                "status": status,
                "reason_codes": reason_codes,
            }
        )

    def _cached_response(
        self, cached: dict, url: str, context: str
    ) -> PhishingDetectionResponse:
        confidence = float(cached.get("confidence", 0.0))
        return self._build_response(
            url=url,
            source="cache",
            confidence=confidence,
            fetch_mode="none",
            severity=self._model_severity(confidence, context),
        )

    def close(self) -> None:
        self.fetcher.close()
        # Best-effort cancel of in-flight background analyses (sync context, so
        # we cancel without awaiting). Class-level state is shared across instances.
        for task in list(self._bg_tasks):
            task.cancel()
        self._bg_tasks.clear()
        self._bg_inflight_keys.clear()

    async def _check_reputation(
        self, input_url: str, canonical_url: str
    ) -> Optional[PhishingDetectionResponse]:
        """Run the URL reputation stage.

        Returns a phishing response when a provider flags the URL as malicious,
        otherwise None (clean/unknown/disabled) so analysis continues. Fail-open:
        any error degrades to None rather than blocking the pipeline.
        """
        try:
            result = await self.reputation_service.check(input_url)
        except Exception as exc:
            logger.warning(f"Reputation stage failed for {canonical_url}: {exc}")
            return None

        if result is None or not result.is_malicious:
            return None

        logger.info(f"URL {canonical_url} flagged malicious by {result.source}")
        return self._build_response(
            url=canonical_url,
            source=result.source,
            confidence=result.confidence,
            fetch_mode="none",
            severity="block",
            reason_codes=result.reason_codes or None,
        )

    async def _cleanup_inflight_task(
        self,
        key: str,
        task: asyncio.Task[PhishingDetectionResponse],
    ) -> None:
        try:
            task.exception()
        except asyncio.CancelledError:
            pass

        async with self._inflight_lock:
            if self._inflight_tasks.get(key) is task:
                self._inflight_tasks.pop(key, None)

    async def _run_inflight_deduplicated(
        self,
        key: str,
        work: Callable[[], Awaitable[PhishingDetectionResponse]],
    ) -> PhishingDetectionResponse:
        async with self._inflight_lock:
            existing = self._inflight_tasks.get(key)
            if existing is None:
                existing = asyncio.create_task(work())
                self._inflight_tasks[key] = existing
                existing.add_done_callback(
                    lambda task, inflight_key=key: asyncio.create_task(
                        self._cleanup_inflight_task(inflight_key, task)
                    )
                )

        return await asyncio.shield(existing)

    async def _fetch_html_once(self, url: str) -> tuple[str | None, str, str | None]:
        http_result = await asyncio.to_thread(self.fetcher.http_fetcher.fetch, url)
        if http_result is not None:
            # Non-HTML resources must never be escalated to the browser.
            if not is_html_content_type(http_result.content_type):
                return http_result.html, "http", http_result.content_type
            if not self.fetcher._is_low_quality_html(http_result.html):
                return http_result.html, "http", http_result.content_type

        async with self.browser_semaphore:
            browser_result = await asyncio.to_thread(
                self.fetcher.browser_fetcher.fetch,
                url,
            )
        if browser_result:
            return browser_result.html, "browser", browser_result.content_type

        if http_result:
            return http_result.html, "http", http_result.content_type

        return None, "none", None

    async def _persist_result(
        self,
        db_manager: DBManager,
        url: str,
        is_phishing: bool,
        confidence: float,
        html_content: str | None,
        timer: StageTimer,
    ) -> None:
        # ``is_phishing`` is the operational BLOCK decision (severity == "block"),
        # not the raw model positive (prob >= 0.5). So a low-confidence positive
        # that the policy does not block is NOT recorded as phishing.
        timer.start("db_write")
        # Durable PostgreSQL history: persist block-worthy verdicts; non-block
        # (benign/warn) only when explicitly enabled (avoids write amplification +
        # unbounded growth, since most analyzed URLs are not blocked).
        if is_phishing or settings.PERSIST_BENIGN:
            await asyncio.to_thread(
                db_manager.save_phishing_url,
                url,
                is_phishing,
                confidence,
                html_content,
            )
        # Redis cache: every verdict, for the fast repeat path (severity is
        # recomputed from confidence on read).
        await db_manager.cache_result(
            url=url,
            is_phishing=is_phishing,
            confidence=confidence,
        )
        timer.stop("db_write")

    def _record_perf(
        self,
        *,
        url: str,
        source: str,
        timer: StageTimer,
        fetch_mode: str | None,
        cache_hit: bool,
    ) -> None:
        if not settings.ENABLE_PERF_RECORDS:
            return

        record = build_perf_record(
            url=url,
            source=source,
            timer=timer,
            fetch_mode=fetch_mode,
            cache_hit=cache_hit,
        )
        log_perf_record(record)

    async def analyze(
        self,
        url: str,
        request: Request,
        db_manager: Optional[DBManager] = None,
        context: str = "navigation",
    ) -> PhishingDetectionResponse:
        input_url = url.strip()
        if not input_url:
            raise BackendExceptions("URL must not be empty")
        canonical_url = canonicalize_url(input_url)
        logger.info(f"Analyzing URL: {input_url} (canonical: {canonical_url})")

        redis_client = await get_redis()
        domain_checker = DomainChecker(redis_client)

        # Authoritative BLOCK signals are checked BEFORE the whitelist so that a
        # known-bad URL on an otherwise-trusted, coarse (registrable-level)
        # whitelisted domain — e.g. a phishing page on sites.google.com under the
        # whitelisted google.com — is still blocked instead of bypassing
        # reputation entirely.
        #
        # Order: blacklist (operator) -> reputation (external TI) -> whitelist
        #        (trusted, skip model) -> analysis cache -> HTML model.

        # 1. Operator blacklist (local, authoritative deny).
        if await domain_checker.is_blacklisted(input_url):
            logger.info(f"URL {canonical_url} is in blacklist")
            return self._build_response(
                url=canonical_url,
                source="blacklist",
                confidence=0.99,
                fetch_mode="none",
                severity="block",
            )

        # 2. URL reputation (external TI). Malicious overrides the whitelist; it
        #    also covers non-HTML/download URLs the model would skip. Fail-open.
        reputation_response = await self._check_reputation(input_url, canonical_url)
        if reputation_response is not None:
            return reputation_response

        # 3. Whitelist (trusted -> allow, skip the model). Reached only when the
        #    URL is neither blacklisted nor flagged malicious.
        if await domain_checker.is_whitelisted(input_url):
            logger.info(f"URL {canonical_url} is in whitelist")
            return self._build_response(
                url=canonical_url,
                source="whitelist",
                confidence=0.01,
                fetch_mode="none",
                severity="allow",
            )

        if db_manager is None:
            db_manager = DBManager()

        detector = request.app.state.model

        if context == "link":
            # Links: reputation-only + cache-first. On a cache miss, optionally
            # schedule a bounded background model run and return a neutral pending.
            cached_result = await db_manager.get_cached_result(canonical_url)
            if cached_result:
                return self._cached_response(cached_result, canonical_url, context)
            self._maybe_schedule_background(
                detector, db_manager, input_url, canonical_url
            )
            return self._build_response(
                url=canonical_url,
                source="pending",
                confidence=0.0,
                fetch_mode="none",
                severity="allow",
                status="pending",
            )

        return await self._run_inflight_deduplicated(
            canonical_url,
            lambda: self._analyze_with_model(
                detector, db_manager, input_url, canonical_url, context
            ),
        )

    async def _analyze_with_model(
        self,
        detector,
        db_manager: DBManager,
        input_url: str,
        canonical_url: str,
        context: str,
    ) -> PhishingDetectionResponse:
        timer = StageTimer()
        timer.start("cache_lookup")
        cached_result = await db_manager.get_cached_result(canonical_url)
        timer.stop("cache_lookup")
        if cached_result:
            self._record_perf(
                url=canonical_url,
                source="cache",
                timer=timer,
                fetch_mode="none",
                cache_hit=True,
            )
            return self._cached_response(cached_result, canonical_url, context)

        timer.start("html_fetch")
        try:
            html_content, fetch_mode, content_type = await self._fetch_html_once(
                input_url
            )
        except SSRFBlockedError:
            timer.stop("html_fetch")
            logger.warning(f"SSRF guard blocked fetch for {canonical_url}")
            return self._build_response(
                url=canonical_url,
                source="blocked_private",
                confidence=0.0,
                fetch_mode="none",
                severity="allow",
            )
        timer.stop("html_fetch")

        if not is_html_content_type(content_type):
            # Non-HTML resource (image/svg/pdf/zip/binary): not valid input for the
            # HTML model. Benign without model/browser/cache.
            logger.info(
                f"Skipping non-HTML resource {canonical_url} "
                f"(content-type={content_type})"
            )
            self._record_perf(
                url=canonical_url,
                source="non_html",
                timer=timer,
                fetch_mode=fetch_mode,
                cache_hit=False,
            )
            return self._build_response(
                url=canonical_url,
                source="non_html",
                confidence=0.0,
                fetch_mode=fetch_mode,
                severity="allow",
            )

        if not html_content:
            return self._build_response(
                url=canonical_url,
                source="error",
                confidence=0.0,
                fetch_mode=fetch_mode,
                severity="allow",
            )

        async with self.infer_semaphore:
            model_result = await asyncio.to_thread(
                detector.predict_from_html,
                input_url,
                html_content,
            )

        if model_result["confidence"] is None:
            return self._build_response(
                url=canonical_url,
                source="error",
                confidence=0.0,
                fetch_mode=fetch_mode,
                severity="allow",
            )

        timer.stages["preprocess"] = model_result.get("preprocess_ms", 0.0)
        timer.stages["inference"] = model_result.get("infer_ms", 0.0)

        confidence = float(model_result["confidence"])
        severity = self._model_severity(confidence, context)

        # Persist the operational BLOCK decision (not the raw prob>=0.5 positive),
        # so a low-confidence, non-blocked positive is not logged as phishing.
        #
        # Persistence (history + cache) is a side effect, never part of the verdict:
        # a Postgres/Redis hiccup must not turn an already-computed "block" into the
        # caller's error fallback (result=False / severity="allow"), which would be
        # a fail-open. Degrade to a log line and return the verdict as computed.
        try:
            await self._persist_result(
                db_manager=db_manager,
                url=canonical_url,
                is_phishing=(severity == "block"),
                confidence=confidence,
                html_content=html_content,
                timer=timer,
            )
        except Exception as exc:
            # Close the dangling db_write mark so the perf record keeps the time
            # spent before the failure instead of reporting 0.
            timer.stop("db_write")
            logger.error(f"Failed to persist result for {canonical_url}: {exc}")

        self._record_perf(
            url=canonical_url,
            source="model",
            timer=timer,
            fetch_mode=fetch_mode,
            cache_hit=False,
        )

        return self._build_response(
            url=canonical_url,
            source="model",
            confidence=confidence,
            fetch_mode=fetch_mode,
            severity=severity,
        )

    def _maybe_schedule_background(
        self, detector, db_manager: DBManager, input_url: str, canonical_url: str
    ) -> None:
        if not settings.LINK_BACKGROUND_MODEL:
            return
        # Dedup duplicate schedules for the same canonical URL up front, so a
        # link batch with repeats doesn't spawn N tasks just to dedup later.
        if canonical_url in self._bg_inflight_keys:
            return
        if len(self._bg_tasks) >= settings.LINK_BG_MAX_INFLIGHT:
            logger.warning("Link background queue full; dropping %s", canonical_url)
            return
        self._bg_inflight_keys.add(canonical_url)
        task = asyncio.create_task(
            self._background_model(detector, db_manager, input_url, canonical_url)
        )
        self._bg_tasks.add(task)

        def _done(completed: asyncio.Task, key: str = canonical_url) -> None:
            self._bg_tasks.discard(completed)
            self._bg_inflight_keys.discard(key)

        task.add_done_callback(_done)

    async def _background_model(
        self, detector, db_manager: DBManager, input_url: str, canonical_url: str
    ) -> None:
        async with self._bg_semaphore:
            try:
                await self._run_inflight_deduplicated(
                    canonical_url,
                    lambda: self._analyze_with_model(
                        detector, db_manager, input_url, canonical_url, "navigation"
                    ),
                )
            except Exception as exc:
                logger.warning(
                    "Background analysis failed for %s: %s", canonical_url, exc
                )
