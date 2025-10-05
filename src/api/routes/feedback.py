# --------------------------------------------------------------------------
# Feedback route module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends

from src.database import DBManager
from src.api.deps import get_db_manager
from src.schemas.common import ResponseSchema
from src.schemas.feedback import UserFeedbackRequest
from src.enums import ResponseMessage
from src.orm_models import UserFeedback

logger = logging.getLogger("main")

router = APIRouter(prefix="/feedback", tags=["feedback"])


def save_feedback(
    feedback: UserFeedbackRequest, db_manager: Optional[DBManager] = None
) -> Dict[str, Any]:
    """Save user feedback"""
    logger.info(f"Saving feedback for URL: {feedback.url}")

    if db_manager is None:
        db_manager = DBManager()

    # Save feedback to MongoDB
    user_feedback = UserFeedback(
        url=feedback.url,  # Feedback target URL
        is_correct=feedback.is_correct,  # User decision result
        user_comment=feedback.comment,  # User comment
        detected_result=feedback.detected_result,  # Model decision result
        confidence=feedback.confidence,  # Model decision confidence
        metadata=feedback.metadata,  # Save rating etc.
    )

    feedback_id = db_manager.save_user_feedback(user_feedback)

    return {"feedback_id": feedback_id, "status": "success"}


@router.post("/feedback", response_model=ResponseSchema[dict])
def submit_feedback(
    data: UserFeedbackRequest, db_manager: DBManager = Depends(get_db_manager)
):
    """
    Submit user feedback endpoint
    """
    result = save_feedback(data, db_manager=db_manager)
    response: ResponseSchema[dict] = ResponseSchema(
        timestamp=datetime.now().isoformat(),
        message=ResponseMessage.SUCCESS,
        data=result,
    )
    return response
