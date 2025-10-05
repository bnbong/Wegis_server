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
from datetime import datetime
import asyncio

logger = logging.getLogger("main")

router = APIRouter(prefix="/analyze", tags=["analyze"])


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
    db_manager: DBManager = Depends(get_db_manager),
):
    """
    Single URL phishing detection endpoint
    """
    analyzer = AnalyzerService()
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
    urls: List[str],
    request: Request,
    db_manager: DBManager = Depends(get_db_manager),
):
    """
    Batch URL phishing detection endpoint for browser extensions
    """

    async def analyze_single_url(url: str) -> PhishingDetectionResponse:
        analyzer = AnalyzerService()
        return await analyzer.analyze(
            url=url,
            request=request,
            db_manager=db_manager,
        )

    # 비동기로 여러 URL을 동시에 처리
    tasks = [analyze_single_url(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 예외가 발생한 경우 에러 응답으로 변환
    processed_results: List[PhishingDetectionResponse] = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Error analyzing URL {urls[i]}: {result}")
            processed_results.append(
                PhishingDetectionResponse(result=False, confidence=0.0, source="error")
            )
        elif isinstance(result, PhishingDetectionResponse):
            processed_results.append(result)

    response: ResponseSchema[List[PhishingDetectionResponse]] = ResponseSchema(
        timestamp=datetime.now().isoformat(),
        message=ResponseMessage.SUCCESS,
        data=processed_results,
    )
    return response
