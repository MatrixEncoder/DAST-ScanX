"""
main.py — FastAPI application entry point for Scan-X.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db
from backend.api import targets, scans, findings, reports

# ─────────────────────────────── Logging ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("scanx")


# ─────────────────────────────── Lifespan ─────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Scan-X starting — initializing database...")
    init_db()
    logger.info("Database ready.")
    yield
    logger.info("Scan-X shutting down.")


# ─────────────────────────────── App ──────────────────────────────────────────
app = FastAPI(
    title="Scan-X DAST Platform",
    description=(
        "Dynamic Application Security Testing platform for web vulnerability scanning, "
        "risk scoring, and security reporting."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ─────────────────────────────── CORS ─────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────── Routers ──────────────────────────────────────
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)


# ─────────────────────────────── Health ───────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "platform": "Scan-X", "version": "1.0.0"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}
