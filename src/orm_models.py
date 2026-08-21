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


class Feedback(SQLModel, table=True):
    """User-reported false positive / false negative (POST /feedback).

    Rows are a REVIEW QUEUE, never a rule source: every column here is
    attacker-controlled input, so feeding `user_label` straight into the
    blacklist/whitelist would hand anyone a way to poison verdicts (mass
    "false_positive" reports to unblock a phishing page, mass "false_negative"
    reports to blocklist a competitor). Rows therefore land as
    review_status="pending" and are promoted only by an offline, reviewed step.
    """

    __tablename__ = "feedback_reports"
    __table_args__ = (
        CheckConstraint(
            "review_status IN ('pending', 'reviewed', 'applied', 'rejected')",
            name="ck_feedback_reports_review_status",
        ),
    )

    id: Optional[int] = SQLField(default=None, primary_key=True)
    url: str = SQLField(index=True)  # canonicalized, matches the analysis cache key
    reported_verdict: Optional[str] = None
    user_label: Optional[str] = None
    context: Optional[str] = None
    ext_version: Optional[str] = None
    # SHA-256 of the caller's token, or of its IP when no token was sent. The
    # raw identifier is never stored.
    client_id_hash: str = SQLField(index=True)
    review_status: str = SQLField(default="pending")
    created_at: datetime = SQLField(default_factory=datetime.now)
