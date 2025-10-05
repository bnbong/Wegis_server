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
from src.logger import Logger
from src.database import DBManager
from src.services.model.manager import PhishingDetector
from src.orm_models import UserFeedback
from src.api.main import router as api_router
from src.clients.redis import init_redis, close_redis
from src.clients.mongo import init_mongo, close_mongo


logger = Logger(file_path=f"./log/{datetime.now().strftime('%Y-%m-%d')}", name="main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        logger.info("Starting server...")

        # Initialize Redis client
        logger.info("Initializing Redis connection...")
        await init_redis()

        # Initialize MongoDB client and Beanie
        logger.info("Initializing MongoDB connection...")
        await init_mongo(document_models=[UserFeedback])

        # Initialize PostgreSQL database manager
        logger.info("Initializing PostgreSQL database manager...")
        app.state.db_manager = DBManager()

        # Load AI model
        logger.info("Loading AI model...")
        app.state.model = PhishingDetector(model_path=settings.MODEL_PATH)

        logger.info("Application startup complete")

        yield
    finally:
        logger.info("Shutting down server...")

        # Close PostgreSQL connection
        if hasattr(app.state, "db_manager"):
            logger.info("Closing PostgreSQL connections...")
            app.state.db_manager.close()

        # Unload AI model
        app.state.model = None
        logger.info("AI model unloaded")

        # Close MongoDB connection
        logger.info("Closing MongoDB connection...")
        await close_mongo()

        # Close Redis connection
        logger.info("Closing Redis connection...")
        await close_redis()

        logger.info("Application shutdown complete")


app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
)

if settings.all_cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.all_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


app.include_router(api_router)
