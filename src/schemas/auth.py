# --------------------------------------------------------------------------
# Auth schema module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from pydantic import BaseModel


class RegisterRequest(BaseModel):
    # Optional extension version for observability.
    ext_version: str | None = None


class RegisterResponse(BaseModel):
    token: str
    install_id: str
