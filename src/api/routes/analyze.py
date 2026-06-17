# --------------------------------------------------------------------------
# Analyze route module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
from typing import List
from fastapi import APIRouter, Depends, Query, Request, HTTPException

from src.database import DBManager
from src.core.config import settings
from src.schemas.common import ResponseSchema
from src.schemas.analyze import (
    PhishingURLListResponse,
    PhishingDetectionRequest,
    PhishingDetectionResponse,
    NonEmptyURL,
)
from src.enums import ResponseMessage
from src.api.deps import get_db_manager
from src.services.analyzer import AnalyzerService
from src.services.perf_store import perf_store
import asyncio
from datetime import datetime

logger = logging.getLogger("main")

router = APIRouter(prefix="/analyze", tags=["analyze"])


def ensure_perf_records_access() -> None:
    if not settings.ENABLE_PERF_RECORDS:
        raise HTTPException(status_code=403, detail="Performance records unavailable")


@router.get("/perf/records")
async def get_perf_records():
    ensure_perf_records_access()
    records = await perf_store.list()
    return {
        "timestamp": datetime.now().isoformat(),
        "count": len(records),
        "data": records,
    }


@router.delete("/perf/records")
async def clear_perf_records():
    ensure_perf_records_access()
    await perf_store.clear()
    return {"timestamp": datetime.now().isoformat(), "message": "cleared"}


@router.get("/recent", response_model=ResponseSchema[PhishingURLListResponse])
def get_recent_phishing(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db_manager: DBManager = Depends(get_db_manager),
):
    """
    Recent URL detection request list endpoint
    """
    logger.info(f"Fetching recent phishing URLs, limit: {limit}, offset: {offset}")
    urls = [
        {
            "url": url.url,
            "is_phishing": url.is_phishing,
            "confidence": url.confidence,
            "detection_time": url.detection_time.isoformat(),
        }
        for url in db_manager.get_phishing_urls(limit=limit, offset=offset)
    ]
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


@router.post("/check", response_model=ResponseSchema[PhishingDetectionResponse])
async def check_url(
    request_data: PhishingDetectionRequest,
    request: Request,
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
    )

    response: ResponseSchema[PhishingDetectionResponse] = ResponseSchema(
        timestamp=datetime.now().isoformat(),
        message=ResponseMessage.SUCCESS,
        data=result,
    )
    return response


@router.post("/batch", response_model=ResponseSchema[List[PhishingDetectionResponse]])
async def check_urls_batch(
    urls: List[NonEmptyURL],
    request: Request,
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
