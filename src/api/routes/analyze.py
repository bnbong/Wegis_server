# --------------------------------------------------------------------------
# Analyze route module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse

from src.database import DBManager
from src.schemas.common import ResponseSchema
from src.schemas.analyze import (
    PhishingURLListResponse,
    PhishingDetectionRequest,
    PhishingDetectionResponse,
)
from src.enums import ResponseMessage
from src.api.deps import get_db_manager
from src.services.analyzer import AnalyzerService
from src.services.perf_store import perf_store
import asyncio
from datetime import datetime

logger = logging.getLogger("main")

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.get("/perf/records")
async def get_perf_records(
    scenario: str = Query("", description="Filter by scenario: baseline or optimized"),
):
    target = scenario or None
    records = await perf_store.list(target)
    return {
        "timestamp": datetime.now().isoformat(),
        "count": len(records),
        "data": records,
    }


@router.delete("/perf/records")
async def clear_perf_records():
    await perf_store.clear()
    return {"timestamp": datetime.now().isoformat(), "message": "cleared"}


def get_recent_phishing_urls(
    limit: int = 100, offset: int = 0, db_manager: Optional[DBManager] = None
) -> list:
    """Get recent phishing URL list"""
    logger.info(f"Fetching recent phishing URLs, limit: {limit}, offset: {offset}")

    if db_manager is None:
        db_manager = DBManager()

    urls = db_manager.get_phishing_urls(limit=limit, offset=offset)

    return [
        {
            "url": url.url,
            "is_phishing": url.is_phishing,
            "confidence": url.confidence,
            "detection_time": url.detection_time.isoformat(),
        }
        for url in urls
    ]


@router.get("/recent", response_model=ResponseSchema[PhishingURLListResponse])
def get_recent_phishing(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db_manager: DBManager = Depends(get_db_manager),
):
    """
    Recent URL detection request list endpoint
    """
    urls = get_recent_phishing_urls(db_manager=db_manager, limit=limit, offset=offset)
    result = PhishingURLListResponse(
        urls=urls,
        total=len(urls),
        limit=limit,
        offset=offset,
    )
    response: ResponseSchema[PhishingURLListResponse] = ResponseSchema(
        timestamp=datetime.now().isoformat(),
        message=ResponseMessage.SUCCESS,
        data=result,
    )
    return response


@router.post("")
async def check_legacy():
    """
    Legacy URL phishing detection endpoint
    """
    return RedirectResponse(url="/analyze/check")


@router.post("/check", response_model=ResponseSchema[PhishingDetectionResponse])
async def check_url(
    request_data: PhishingDetectionRequest,
    request: Request,
    pipeline_mode: str = Query("optimized", pattern="^(optimized|baseline)$"),
    db_manager: DBManager = Depends(get_db_manager),
):
    """
    Single URL phishing detection endpoint
    """
    analyzer = getattr(request.app.state, "analyzer_service", None) or AnalyzerService()
    result = await analyzer.analyze(
        url=request_data.url,
        request=request,
        db_manager=db_manager,
        pipeline_mode=pipeline_mode,
    )

    response: ResponseSchema[PhishingDetectionResponse] = ResponseSchema(
        timestamp=datetime.now().isoformat(),
        message=ResponseMessage.SUCCESS,
        data=result,
    )
    return response


@router.post("/batch", response_model=ResponseSchema[List[PhishingDetectionResponse]])
async def check_urls_batch(
    urls: List[str],
    request: Request,
    pipeline_mode: str = Query("optimized", pattern="^(optimized|baseline)$"),
    db_manager: DBManager = Depends(get_db_manager),
):
    """
    Batch URL phishing detection endpoint for browser extensions
    """

    analyzer = getattr(request.app.state, "analyzer_service", None) or AnalyzerService()

    async def analyze_single_url(url: str) -> PhishingDetectionResponse:
        return await analyzer.analyze(
            url=url,
            request=request,
            db_manager=db_manager,
            pipeline_mode=pipeline_mode,
        )

    deduped_urls: list[str] = list(dict.fromkeys(urls))
    tasks = {url: asyncio.create_task(analyze_single_url(url)) for url in deduped_urls}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    result_map: dict[str, PhishingDetectionResponse] = {}
    for url, result in zip(tasks.keys(), gathered):
        if isinstance(result, PhishingDetectionResponse):
            result_map[url] = result
            continue
        logger.error(f"Error analyzing URL {url}: {result}")
        result_map[url] = PhishingDetectionResponse(
            url=url,
            result=False,
            confidence=0.0,
            source="error",
            fetch_mode="none",
        )

    processed_results: List[PhishingDetectionResponse] = []
    for url in urls:
        processed_results.append(result_map[url])

    response: ResponseSchema[List[PhishingDetectionResponse]] = ResponseSchema(
        timestamp=datetime.now().isoformat(),
        message=ResponseMessage.SUCCESS,
        data=processed_results,
    )
    return response
