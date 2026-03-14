"""
Extension Risk Intelligence Platform — FastAPI application.

Run with:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

# Ensure src/ is on the import path so the analyzer engine is importable
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from api.database import engine, Base
from api.routes import analyze, reports, extensions, web


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables on startup (dev convenience — use Alembic in prod)."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Extension Risk Intelligence Platform",
    description=(
        "API-driven extension security analysis for Chrome, Edge, and VSCode extensions. "
        "Submit scans, track progress, retrieve structured risk reports."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow dashboard / external integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount route modules
app.include_router(analyze.router)
app.include_router(reports.router)
app.include_router(extensions.router)
app.include_router(web.router)


@app.get("/", tags=["health"])
def root(request: Request):
    # Browser requests (Accept: text/html) go to the web app; API clients get JSON
    accept = (request.headers.get("accept") or "").lower()
    if "text/html" in accept:
        return RedirectResponse(url="/app", status_code=302)
    return {
        "service": "Extension Risk Intelligence Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "app": "/app",
    }


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
