from dotenv import load_dotenv
load_dotenv()

import os
from pathlib import Path
from contextlib import asynccontextmanager

import psycopg2
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from src.api.report_endpoint import router_report
from src.api.health import router as health_router

DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_DSN")
FRONTEND_DIR = Path(__file__).parent / "frontend"

_conn = None

def get_db():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(DATABASE_URL)
    return _conn

@asynccontextmanager
async def lifespan(app: FastAPI):
    get_db()
    yield
    if _conn and not _conn.closed:
        _conn.close()

app = FastAPI(
    title="AIFinancialCrime API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(router_report, prefix="/api")
app.include_router(health_router, prefix="/api")

# Frontend
@app.get("/intake", include_in_schema=False)
async def intake():
    return FileResponse(str(FRONTEND_DIR / "index.html"))

@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(str(FRONTEND_DIR / "index.html"))
