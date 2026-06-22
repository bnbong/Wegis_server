# --------------------------------------------------------------------------
# Analyze schema module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from typing import List, Dict, Any, Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints


NonEmptyURL = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

# How the page-discovered URL should be analysed (design 01).
AnalysisContext = Literal["navigation", "link"]


class PhishingDetectionRequest(BaseModel):
    url: NonEmptyURL
    # "navigation" = the page the user is viewing (full pipeline);
    # "link" = a link discovered on the page (reputation-only + cache-first).
    context: AnalysisContext = "navigation"


class PhishingDetectionResponse(BaseModel):
    url: str = ""
    result: bool
    confidence: float
    source: str
    fetch_mode: str | None = None
    # Severity tier (design 02): "block" | "warn" | "allow". result == (severity == "block").
    severity: str | None = None
    # "final" | "pending" (design 01): pending = background analysis scheduled.
    status: str | None = None
    # Optional provider metadata, e.g. reputation threat types. Backward
    # compatible: defaults to None and is ignored by the (thin) extension client.
    reason_codes: List[str] | None = None


class PhishingURLListResponse(BaseModel):
    urls: List[Dict[str, Any]] = Field(..., description="Phishing URL list")
    total: int = Field(..., description="Total number of items")
    offset: int = Field(0, description="Start offset")
    limit: int = Field(..., description="Limit number of items")
