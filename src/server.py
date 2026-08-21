# --------------------------------------------------------------------------
# Main server application module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.core.config import settings
from src.logger import setup_logger
from src.database import DBManager
from src.services.model.manager import PhishingDetector
from src.services.analyzer import AnalyzerService
from src.api.main import router as api_router
from src.api.middleware import register_middleware
from src.clients.redis import init_redis, close_redis


logger = setup_logger(
    name="main", file_path=f"./log/{datetime.now().strftime('%Y-%m-%d')}"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        logger.info("Starting server...")

        # Initialize Redis client
        logger.info("Initializing Redis connection...")
        await init_redis()

        # Initialize PostgreSQL database manager
        logger.info("Initializing PostgreSQL database manager...")
        app.state.db_manager = DBManager()

        # Load AI model
        logger.info("Loading AI model...")
        app.state.model = PhishingDetector(model_path=settings.MODEL_PATH)
        app.state.analyzer_service = AnalyzerService()

        logger.info("Application startup complete")

        yield
    finally:
        logger.info("Shutting down server...")

        # Close PostgreSQL connection
        if hasattr(app.state, "db_manager"):
            logger.info("Closing PostgreSQL connections...")
            app.state.db_manager.close()

        # Unload AI model
        if (
            hasattr(app.state, "analyzer_service")
            and app.state.analyzer_service is not None
        ):
            logger.info("Closing analyzer service...")
            app.state.analyzer_service.close()
        app.state.model = None
        app.state.analyzer_service = None
        logger.info("AI model unloaded")

        # Close Redis connection
        logger.info("Closing Redis connection...")
        await close_redis()

        logger.info("Application shutdown complete")


app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
)

# Concurrency cap + rate limiting + optional token auth (fail-open; /analyze
# and /feedback only).
register_middleware(app)

# ORDER MATTERS — CORS must be registered AFTER register_middleware().
# Starlette runs the LAST-registered middleware outermost, so registering CORS
# first would leave auth outside it, and a preflight OPTIONS (which carries no
# X-Wegis-Token) would be answered 401 while also burning the caller's
# auth-failure budget. Outermost CORS short-circuits the preflight and puts CORS
# headers on 401/429 responses too, so the extension can read the status code
# instead of seeing an opaque network error.
if settings.all_cors_origins or settings.CORS_ORIGIN_REGEX:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.all_cors_origins,
        allow_origin_regex=settings.CORS_ORIGIN_REGEX or None,
        allow_credentials=True,
        allow_methods=["*"],
        # Named rather than "*": with allow_credentials=True Starlette answers a
        # "*" allowance by mirroring whatever the preflight asked for, so the
        # wildcard buys nothing and hides what is actually accepted. This list is
        # the client contract (Content-Type, X-Wegis-Token, Accept).
        allow_headers=["Accept", "Content-Type", "X-Wegis-Token"],
    )


app.include_router(api_router)
