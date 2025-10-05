# --------------------------------------------------------------------------
# Analyze schema module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from pydantic import BaseModel, Field
from typing import List, Dict, Any


class PhishingDetectionRequest(BaseModel):
    url: str


class PhishingDetectionResponse(BaseModel):
    result: bool
    confidence: float
    source: str


class PhishingURLListResponse(BaseModel):
    urls: List[Dict[str, Any]] = Field(..., description="Phishing URL list")
    total: int = Field(..., description="Total number of items")
    offset: int = Field(0, description="Start offset")
    limit: int = Field(..., description="Limit number of items")
