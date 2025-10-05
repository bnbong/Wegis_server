# --------------------------------------------------------------------------
# Database model definition module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from datetime import datetime
from typing import Dict, Optional

from beanie import Document
from pydantic import Field
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel


class Base(SQLModel):
    pass


class PhishingURL(Base, table=True):
    """Phishing URL data model"""

    __tablename__ = "phishing_urls"

    id: Optional[int] = SQLField(default=None, primary_key=True)
    url: str = SQLField(index=True)
    is_phishing: bool = SQLField(default=False)
    confidence: float = SQLField(default=0.0)
    detection_time: datetime = SQLField(default_factory=datetime.now)
    html_content: Optional[str] = None
    features: Optional[str] = None  # JSON


# MongoDB model
class UserFeedback(Document):
    """User feedback data model"""

    url: str
    is_correct: bool
    detected_result: bool
    confidence: float
    user_comment: Optional[str] = None
    feedback_time: datetime = Field(default_factory=datetime.now)
    metadata: Optional[Dict] = None

    class Settings:
        name = "user_feedback"
