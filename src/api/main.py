# --------------------------------------------------------------------------
# Health check router module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from datetime import datetime
from typing import Dict

from fastapi import APIRouter, HTTPException, Request, status

from src.exceptions import BackendExceptions
from src.api.routes import analyze, feedback

router = APIRouter()


@router.get("/health")
def health_check(request: Request) -> Dict[str, str]:
    """
    Health check endpoint
    """
    try:
        checks = {
            "status": "ready",
            "timestamp": datetime.now().isoformat(),
            "service": "wegis-server",
        }
        if hasattr(request.app.state, "model") and request.app.state.model is not None:
            checks["model"] = "loaded"
        else:
            checks["model"] = "not_loaded"
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI model is not loaded",
            )
        if (
            hasattr(request.app.state, "db_manager")
            and request.app.state.db_manager is not None
        ):
            checks["db"] = "fetched"
        else:
            checks["db"] = "not_fetched"
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database manager is not fetched with db session",
            )
        return checks

    except Exception as e:
        raise BackendExceptions(f"Health check failed: {str(e)}")


router.include_router(analyze.router)
router.include_router(feedback.router)
