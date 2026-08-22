"""
Brand Intelligence Backend (BIB)
FastAPI entrypoint integrating openSquat and TrustLens-AI for autonomous brand threat defense.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import os
import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from db import init_db
from routers.scans import router as scans_router
from routers.cases import router as cases_router
from schemas import HealthCheckResponse
from tasks.scheduler import start_scheduler, stop_scheduler

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("brand_intelligence")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager: Initializes DB schema and background jobs.
    """
    logger.info("Initializing Brand Intelligence Backend...")
    await init_db()
    logger.info("Database schema initialized.")

    # Validate TrustLens-AI microservice connectivity at startup
    try:
        tl_base = settings.TRUSTLENS_BASE_URL.rstrip("/")
        if "localhost" in tl_base:
            tl_base = tl_base.replace("localhost", "127.0.0.1")
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{tl_base}/health")
            if resp.status_code == 200:
                logger.info("TrustLens-AI service is reachable and healthy at %s", settings.TRUSTLENS_BASE_URL)
            else:
                logger.warning(
                    "⚠️ [WARNING] TrustLens-AI service at %s returned status %d. Running in degraded mode (domain similarity only).",
                    settings.TRUSTLENS_BASE_URL, resp.status_code
                )
    except Exception as e:
        logger.warning(
            "⚠️ [WARNING] TrustLens-AI service is UNREACHABLE at %s (%s). Running in degraded mode (domain similarity only). Inspections will be marked analysis_complete=False.",
            settings.TRUSTLENS_BASE_URL, e
        )

    # Start periodic background scan scheduler
    start_scheduler()
    logger.info("Scheduler initialized with cron: %s", settings.OPENSQUAT_CRON_SCHEDULE)

    yield

    logger.info("Shutting down scheduler...")
    stop_scheduler()
    logger.info("Application shutdown complete.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
## Autonomous Brand Intelligence & Anti-Impersonation Engine
Backend service that orchestrates:
- **openSquat** for typosquatting, lookalike domain mutation, and Newly Registered Domain (NRD) monitoring.
- **TrustLens-AI** for explainable multi-engine deep URL inspection (SSL, DNS, content, screenshots).
- **Risk Scoring Engine** for synthesizing actionable case intelligence.
- **Antigravity Integration** for automated alerting and takedown orchestration.
    """,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(scans_router)
app.include_router(cases_router)

# Mount static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get(
    "/health",
    response_model=HealthCheckResponse,
    tags=["System"],
    summary="Health check",
)
async def health_check():
    """
    Service health check endpoint.
    """
    return HealthCheckResponse(
        status="ok",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        timestamp=datetime.now(timezone.utc),
    )


@app.get(
    "/",
    tags=["System"],
    summary="Root Dashboard UI & Metadata",
)
async def root(request: Request):
    accept_header = request.headers.get("accept", "")
    index_path = os.path.join(STATIC_DIR, "index.html")
    # Return HTML UI if browser specifically requests text/html
    if "text/html" in accept_header and os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "scans": "/scans",
            "cases": "/cases",
            "health": "/health",
            "docs": "/docs",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
