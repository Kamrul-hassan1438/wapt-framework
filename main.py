import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from pathlib import Path

from core.config import settings
from db.database import init_db
from api.routes import targets, scans, reports


# ── Logging setup ──────────────────────────────────────────────────────────
Path("logs").mkdir(exist_ok=True)
logger.add(
    settings.log.file,
    level=settings.log.level,
    format=settings.log.format,
    rotation=settings.log.rotation,
    retention=settings.log.retention,
)

# Suppress SQLAlchemy's verbose INFO logs unless in debug
logging.getLogger("sqlalchemy.engine").setLevel(
    logging.DEBUG if settings.app.env == "development" else logging.WARNING
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""

    logger.info(f"Starting {settings.app.name} v{settings.app.version}")

    Path(settings.report_output_dir).mkdir(parents=True, exist_ok=True)
    Path("reports/output").mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(parents=True, exist_ok=True)

    await init_db()
    logger.success("Database initialized.")

    yield   
    logger.info("Shutting down...")

    
# ── App instance ───────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.app.name,
    version=settings.app.version,
    description=settings.app.description,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "https://webpenetest.netlify.app"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ─────────────────────────────────────────────────────────────────
app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])
app.include_router(scans.router,   prefix="/api/scans",   tags=["Scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/api/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "app": settings.app.name,
        "version": settings.app.version,
        "env": settings.app.env,
    }


# Add this middleware to main.py after creating the app instance:

import time
from core.security import audit

@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Log every API request with timing."""
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000
    audit.log_api_request(request, response.status_code, duration_ms)
    return response
