# --------------------------------------------------------------------------
# Database model definition module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint
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


class APIClient(SQLModel, table=True):
    """Per-install API client (design 05 — registration auth).

    Stores the SHA-256 hash of the issued token (never the plaintext), so a DB
    leak does not expose usable tokens.
    """

    __tablename__ = "api_clients"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_api_clients_status"
        ),
    )

    token_hash: str = SQLField(primary_key=True)
    install_id: str = SQLField(index=True)
    status: str = SQLField(default="active")  # active | revoked
    created_at: datetime = SQLField(default_factory=datetime.now)
    last_seen_at: Optional[datetime] = None
    ext_version: Optional[str] = None
