# --------------------------------------------------------------------------
# Feedback request schema module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class UserFeedbackRequest(BaseModel):
    url: str = Field(..., description="Feedback target URL")
    is_correct: bool = Field(
        ..., description="Whether the AI model decision result is correct"
    )
    comment: Optional[str] = Field(None, description="User feedback content")
    detected_result: bool = Field(..., description="AI model decision result")
    confidence: float = Field(..., description="AI model decision confidence")
    metadata: Optional[Dict[str, Any]] = Field(
        None, description="Additional metadata (rating, browser info, OS etc.)"
    )
