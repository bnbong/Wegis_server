# --------------------------------------------------------------------------
# Analyze schema module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from typing import List, Dict, Any, Annotated

from pydantic import BaseModel, Field, StringConstraints


NonEmptyURL = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class PhishingDetectionRequest(BaseModel):
    url: NonEmptyURL


class PhishingDetectionResponse(BaseModel):
    url: str = ""
    result: bool
    confidence: float
    source: str
    fetch_mode: str | None = None
    # Optional provider metadata, e.g. reputation threat types. Backward
    # compatible: defaults to None and is ignored by the (thin) extension client.
    reason_codes: List[str] | None = None


class PhishingURLListResponse(BaseModel):
    urls: List[Dict[str, Any]] = Field(..., description="Phishing URL list")
    total: int = Field(..., description="Total number of items")
    offset: int = Field(0, description="Start offset")
    limit: int = Field(..., description="Limit number of items")
