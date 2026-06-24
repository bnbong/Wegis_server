# --------------------------------------------------------------------------
# Auth route module (per-install registration, design 05)
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging

from fastapi import APIRouter, HTTPException, Request, status

from src.core.config import settings
from src.api.deps import get_client_ip
from src.schemas.auth import RegisterRequest, RegisterResponse
from src.services.auth_tokens import (
    bootstrap_ok,
    register_client,
    registration_allowed,
)

logger = logging.getLogger("main")

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse)
async def register(request: Request, payload: RegisterRequest) -> RegisterResponse:
    """Issue a per-install API token.

    Unauthenticated (the client has no token yet) but gated by the build-time
    bootstrap secret and a per-IP rate limit.
    """
    if settings.AUTH_MODE != "registration":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if not bootstrap_ok(request.headers.get("x-wegis-bootstrap")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bootstrap secret"
        )

    client_ip = get_client_ip(request)
    if not await registration_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Registration rate limit exceeded",
            headers={"Retry-After": "3600"},
        )

    token, install_id = await register_client(payload.ext_version)
    logger.info("Registered new API client install_id=%s", install_id)
    return RegisterResponse(token=token, install_id=install_id)
