# --------------------------------------------------------------------------
# Feedback route module (user-reported false positives / negatives)
#
# Reports are only appended to a review queue. They are deliberately NOT wired
# into the blacklist/whitelist: the whole payload is user-controlled, so
# auto-applying it is a verdict-poisoning vector (see orm_models.Feedback).
# Promotion to a rule is an offline, reviewed step.
#
# The reported URL is never re-fetched or re-analysed here — that would open an
# attacker-chosen-URL SSRF surface for no benefit at report time.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import asyncio
import logging
from datetime import datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status

from src.database import DBManager
from src.enums import ResponseMessage
from src.schemas.common import ResponseSchema
from src.schemas.feedback import FeedbackRequest, FeedbackResponse
from src.api.deps import get_client_ip, get_db_manager
from src.services.auth_tokens import hash_token

logger = logging.getLogger("main")

router = APIRouter(tags=["feedback"])


def _log_host(url: str) -> str:
    """Host of a reported URL, for logging.

    Never log the full URL: its path and query string can carry session tokens,
    reset links or other data the reporting user did not mean to hand over.
    """
    return urlsplit(url).hostname or "unknown"


@router.post(
    "/feedback",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ResponseSchema[FeedbackResponse],
)
async def submit_feedback(
    request_data: FeedbackRequest,
    request: Request,
    db_manager: DBManager = Depends(get_db_manager),
):
    """
    User feedback endpoint for a verdict the extension displayed
    """
    # Identify the reporter without storing anything reversible: the token when
    # the client sent one, else its IP. Only ever the hash reaches the database.
    token = request.headers.get("x-wegis-token")
    client_id_hash = hash_token(token or get_client_ip(request))

    try:
        await asyncio.to_thread(
            db_manager.save_feedback,
            url=request_data.url,
            client_id_hash=client_id_hash,
            reported_verdict=request_data.reported_verdict,
            user_label=request_data.user_label,
            context=request_data.context,
            ext_version=request_data.ext_version,
        )
    except Exception as exc:
        # The client is fire-and-forget and only checks for a 2xx, which is
        # exactly why we must not answer 202 here: that would claim the report
        # was recorded when nothing was. Report the dependency failure honestly,
        # but as a deliberate response rather than a propagated stack trace.
        logger.error(
            "Failed to persist feedback report host=%s: %s",
            _log_host(request_data.url),
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Feedback storage unavailable",
        )

    logger.info(
        "Feedback queued host=%s label=%s reported=%s context=%s",
        _log_host(request_data.url),
        request_data.user_label,
        request_data.reported_verdict,
        request_data.context,
    )

    response: ResponseSchema[FeedbackResponse] = ResponseSchema(
        timestamp=datetime.now().isoformat(),
        message=ResponseMessage.SUCCESS,
        data=FeedbackResponse(),
    )
    return response
