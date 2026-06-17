# --------------------------------------------------------------------------
# Database model definition module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from datetime import datetime
from typing import Optional

from sqlmodel import Field as SQLField
from sqlmodel import SQLModel


class PhishingURL(SQLModel, table=True):
    """Phishing URL data model"""

    __tablename__ = "phishing_urls"

    id: Optional[int] = SQLField(default=None, primary_key=True)
    url: str = SQLField(index=True)
    is_phishing: bool = SQLField(default=False)
    confidence: float = SQLField(default=0.0)
    detection_time: datetime = SQLField(default_factory=datetime.now)
    html_content: Optional[str] = None
    features: Optional[str] = None  # JSON
