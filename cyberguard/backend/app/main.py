"""
CyberGuard — FastAPI Application Entrypoint
"""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Ensure backend root is on sys.path ──────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings
from app.database import Base, engine
from app.routers import (
    auth_anomaly,
    dashboard,
    deepfake,
    impersonation,
    incidents,
    network,
    phishing,
    url_scan,
)
from app.websocket_manager import ws_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cyberguard")


# ─── Lifespan: DB init + seeding ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create tables and seed synthetic demo data."""
    logger.info("Creating database tables…")
    Base.metadata.create_all(bind=engine)

    # Seed synthetic data on first run
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        from app.models import ThreatEvent
        count = db.query(ThreatEvent).count()
        if count == 0:
            logger.info("Database is empty — seeding synthetic demo data…")
            _seed_database(db)
        else:
            logger.info("Database already has %d events — skipping seed.", count)
    finally:
        db.close()

    yield
    logger.info("CyberGuard shutting down.")


def _seed_database(db):
    """Seed the database with synthetic demo data for live demonstrations."""
    from scripts.seed import seed_all
    try:
        seed_all(db)
        logger.info("Synthetic demo data seeded successfully.")
    except Exception as exc:
        logger.warning("Seeding failed (non-fatal): %s", exc)


# ─── App factory ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "CyberGuard — AI-Powered Cyber Threat, Phishing & Digital Impersonation "
        "Detection and Response System. College Capstone Project."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list + ["*"],  # restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ──────────────────────────────────────────────────────────────────
app.include_router(phishing.router)
app.include_router(url_scan.router)
app.include_router(deepfake.router)
app.include_router(impersonation.router)
app.include_router(auth_anomaly.router)
app.include_router(network.router)
app.include_router(dashboard.router)
app.include_router(incidents.router)


# ─── WebSocket endpoint ───────────────────────────────────────────────────────

@app.websocket("/ws/timeline")
async def websocket_timeline(ws: WebSocket):
    """Live attack timeline WebSocket feed."""
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep connection alive; server pushes events via ws_manager.broadcast()
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


@app.get("/", tags=["System"])
def root():
    return {
        "message": f"Welcome to {settings.APP_NAME} API",
        "docs": "/docs",
        "health": "/health",
    }


# ─── Exception handler ────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Check server logs."},
    )


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info",
    )
