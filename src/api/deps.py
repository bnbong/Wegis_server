# --------------------------------------------------------------------------
# API dependency management module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from starlette.requests import Request

from src.core.config import settings
from src.database import DBManager


def get_db_manager() -> DBManager:
    """
    Provide DB manager instance for API usage
    """
    return DBManager()


def get_client_ip(request: Request) -> str:
    """Resolve the client IP, honoring a trusted-proxy header when configured.

    Behind Cloudflare set CLIENT_IP_HEADER="cf-connecting-ip". When unset we use
    the socket peer. The header is only trustworthy if the origin accepts traffic
    solely from the trusted proxy (else it is spoofable).
    """
    header = settings.CLIENT_IP_HEADER
    if header:
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For style lists put the original client first.
            return value.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
