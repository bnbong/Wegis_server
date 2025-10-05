# --------------------------------------------------------------------------
# Base DTO module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ResponseSchema(BaseModel, Generic[T]):
    timestamp: str = Field(..., description="Response created time")
    message: str = Field(..., description="Response one line message")
    data: T = Field(..., description="Response data")
