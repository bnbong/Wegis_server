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
from src.services.performance import StageTimer, build_perf_record, log_perf_record
from src.services.url_utils import canonicalize_url

logger = logging.getLogger("main")


class AnalyzerService:
    _inflight_lock = asyncio.Lock()
    _inflight_tasks: dict[str, asyncio.Task[PhishingDetectionResponse]] = {}

    def __init__(self):
        self.fetcher = HybridFetcher()
        self.browser_semaphore = asyncio.Semaphore(settings.MAX_BROWSER_CONCURRENCY)
        self.infer_semaphore = asyncio.Semaphore(settings.MAX_INFER_CONCURRENCY)

    def close(self) -> None:
        self.fetcher.close()

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

    async def _fetch_html_once(self, url: str) -> tuple[str | None, str]:
        http_result = await asyncio.to_thread(self.fetcher.http_fetcher.fetch, url)
        if http_result and not self.fetcher._is_low_quality_html(http_result.html):
            return http_result.html, "http"

        async with self.browser_semaphore:
            browser_result = await asyncio.to_thread(
                self.fetcher.browser_fetcher.fetch,
                url,
            )
        if browser_result:
            return browser_result.html, "browser"

        if http_result:
            return http_result.html, "http"

        return None, "none"

    async def _persist_result(
        self,
        db_manager: DBManager,
        url: str,
        result: bool,
        confidence: float,
        html_content: str | None,
        timer: StageTimer,
    ) -> None:
        timer.start("db_write")
        await asyncio.to_thread(
            db_manager.save_phishing_url,
            url,
            result,
            confidence,
            html_content,
        )
        await db_manager.cache_result(
            url=url,
            is_phishing=result,
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
    ) -> PhishingDetectionResponse:
        input_url = url.strip()
        if not input_url:
            raise BackendExceptions("URL must not be empty")
        canonical_url = canonicalize_url(input_url)
        logger.info(f"Analyzing URL: {input_url} (canonical: {canonical_url})")

        redis_client = await get_redis()
        domain_checker = DomainChecker(redis_client)

        if await domain_checker.is_whitelisted(input_url):
            logger.info(f"URL {canonical_url} is in whitelist")
            return PhishingDetectionResponse.model_validate(
                {
                    "url": canonical_url,
                    "result": False,
                    "confidence": 0.01,
                    "source": "whitelist",
                    "fetch_mode": "none",
                }
            )

        if await domain_checker.is_blacklisted(input_url):
            logger.info(f"URL {canonical_url} is in blacklist")
            return PhishingDetectionResponse.model_validate(
                {
                    "url": canonical_url,
                    "result": True,
                    "confidence": 0.99,
                    "source": "blacklist",
                    "fetch_mode": "none",
                }
            )

        if db_manager is None:
            db_manager = DBManager()

        detector = request.app.state.model
        timer = StageTimer()

        async def run_pipeline() -> PhishingDetectionResponse:
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
                return PhishingDetectionResponse.model_validate(
                    {
                        "url": canonical_url,
                        "result": cached_result["is_phishing"],
                        "confidence": cached_result["confidence"],
                        "source": "cache",
                        "fetch_mode": "none",
                    }
                )

            timer.start("html_fetch")
            html_content, fetch_mode = await self._fetch_html_once(input_url)
            timer.stop("html_fetch")
            if not html_content:
                return PhishingDetectionResponse.model_validate(
                    {
                        "url": canonical_url,
                        "result": False,
                        "confidence": 0.0,
                        "source": "error",
                        "fetch_mode": fetch_mode,
                    }
                )

            async with self.infer_semaphore:
                model_result = await asyncio.to_thread(
                    detector.predict_from_html,
                    input_url,
                    html_content,
                )

            if model_result["confidence"] is None:
                return PhishingDetectionResponse.model_validate(
                    {
                        "url": canonical_url,
                        "result": False,
                        "confidence": 0.0,
                        "source": "error",
                        "fetch_mode": fetch_mode,
                    }
                )

            timer.stages["preprocess"] = model_result.get("preprocess_ms", 0.0)
            timer.stages["inference"] = model_result.get("infer_ms", 0.0)

            await self._persist_result(
                db_manager=db_manager,
                url=canonical_url,
                result=bool(model_result["result"]),
                confidence=float(model_result["confidence"]),
                html_content=html_content,
                timer=timer,
            )

            self._record_perf(
                url=canonical_url,
                source="model",
                timer=timer,
                fetch_mode=fetch_mode,
                cache_hit=False,
            )

            return PhishingDetectionResponse.model_validate(
                {
                    "url": canonical_url,
                    "result": bool(model_result["result"]),
                    "confidence": float(model_result["confidence"]),
                    "source": "model",
                    "fetch_mode": fetch_mode,
                }
            )

        return await self._run_inflight_deduplicated(canonical_url, run_pipeline)
