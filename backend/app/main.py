from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import (
    CORSMiddleware,
)

from app.api.routes.email import (
    router as email_router,
)

from app.api.routes.health import (
    router as health_router,
)

from app.core.config import settings

from app.core.database import (
    close_mongo_connection,
    connect_to_mongo,
)


@asynccontextmanager
async def lifespan(
    app: FastAPI,
):

    await connect_to_mongo()

    yield

    await close_mongo_connection()


app = FastAPI(
    title=settings.app_name,
    version="0.4.0",
    description=(
        "PhishingTrack Phase 3 - "
        "IP and Sender Intelligence"
    ),
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,

    allow_origins=(
        settings.cors_origin_list
    ),

    allow_credentials=True,

    allow_methods=[
        "*"
    ],

    allow_headers=[
        "*"
    ],
)


@app.get("/")
async def root():

    return {
        "name": "PhishingTrack API",
        "version": "0.4.0",
        "status": "online",
        "phase": "Phase 3",
    }


app.include_router(
    health_router,
    prefix=settings.api_prefix,
)

app.include_router(
    email_router,
    prefix=settings.api_prefix,
)