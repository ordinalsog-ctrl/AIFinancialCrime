"""
src/api/main.py
Hauptanwendung — FastAPI mit allen Routern + Frontend-Serving

Starte mit:
    uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 2

Das React-Build liegt in /static/ (nach `npm run build` im frontend/-Ordner).
FastAPI serviert es direkt — kein separater Webserver nötig.
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path

import psycopg2
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.api.fraud_report import router as fraud_router
from src.api.cases import router as cases_router

DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_DSN")
STATIC_DIR   = Path(__file__).parent.parent.parent / "static"

# ── DB Connection (einfach, single-process) ──────────────────────────────────
_conn = None

def get_db():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(DATABASE_URL)
    return _conn


# ── App ───────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    get_db()
    yield
    # Shutdown
    if _conn and not _conn.closed:
        _conn.close()

app = FastAPI(
    title="AIFinancialCrime API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Dependency override: inject get_db ───────────────────────────────────────
from src.api import cases as cases_module
from src.api import fraud_report as fraud_module
cases_module.get_db = get_db
fraud_module.get_db = get_db

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(fraud_router, prefix="/api")
app.include_router(cases_router, prefix="/api")

# ── Frontend (React build) ────────────────────────────────────────────────────
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(request: Request, full_path: str):
        """Alle nicht-API-Routes an React weiterleiten (SPA-Routing)."""
        index = STATIC_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return {"error": "Frontend not built. Run: cd frontend && npm run build"}
