"""
AIFinancialCrime — Health Check Endpoints
==========================================
Provides /health, /health/db, /health/blockchain, /health/system
for monitoring, load-balancers, and Prometheus scraping.

GET /health          → lightweight liveness probe (always fast)
GET /health/ready    → readiness probe (checks DB + disk)
GET /health/db       → database connectivity + pool stats
GET /health/blockchain → Blockstream API reachability + tip height
GET /health/system   → disk, memory, CPU (Raspberry Pi aware)
GET /health/full     → all checks combined (for dashboards)
"""

import os
import time
import asyncio
import platform
import shutil
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from src.core.logging_config import get_logger

logger = get_logger("aifc.health")
router = APIRouter(prefix="/health", tags=["Health"])

# ---------------------------------------------------------------------------
# Startup time (for uptime calculation)
# ---------------------------------------------------------------------------
_STARTUP_TS = time.monotonic()
_BUILD_VERSION = os.getenv("AIFC_VERSION", "dev")
_ENV = os.getenv("AIFC_ENV", "production")


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ComponentStatus(BaseModel):
    status: str          # "ok" | "degraded" | "error"
    latency_ms: Optional[float] = None
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str          # "healthy" | "degraded" | "unhealthy"
    version: str
    env: str
    uptime_seconds: float
    timestamp: str
    components: dict[str, ComponentStatus] = {}


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

async def _check_db(db_url: Optional[str] = None) -> ComponentStatus:
    """Ping PostgreSQL via asyncpg."""
    t0 = time.monotonic()
    db_url = db_url or os.getenv("DATABASE_URL", "")
    if not db_url:
        return ComponentStatus(status="error", detail="DATABASE_URL not set")
    try:
        import asyncpg
        conn = await asyncio.wait_for(asyncpg.connect(db_url), timeout=3.0)
        await conn.fetchval("SELECT 1")
        # Check attribution table exists
        tables = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'"
        )
        table_names = {r["tablename"] for r in tables}
        await conn.close()
        latency = round((time.monotonic() - t0) * 1000, 1)
        missing = {"attribution_addresses", "fraud_investigations"} - table_names
        if missing:
            return ComponentStatus(
                status="degraded",
                latency_ms=latency,
                detail=f"Missing tables: {missing}",
            )
        return ComponentStatus(status="ok", latency_ms=latency)
    except asyncio.TimeoutError:
        return ComponentStatus(status="error", detail="DB connection timeout (>3s)")
    except ImportError:
        return ComponentStatus(status="error", detail="asyncpg not installed")
    except Exception as e:
        return ComponentStatus(status="error", detail=str(e)[:120])


async def _check_blockchain() -> ComponentStatus:
    """Ping Blockstream API — check tip height reachability."""
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get("https://blockstream.info/api/blocks/tip/height")
            r.raise_for_status()
            height = int(r.text.strip())
        latency = round((time.monotonic() - t0) * 1000, 1)
        return ComponentStatus(
            status="ok",
            latency_ms=latency,
            detail=f"tip_height={height}",
        )
    except httpx.TimeoutException:
        return ComponentStatus(status="degraded", detail="Blockstream API timeout")
    except Exception as e:
        return ComponentStatus(status="degraded", detail=str(e)[:120])


def _check_disk() -> ComponentStatus:
    """Check NVMe / data disk usage."""
    try:
        data_path = os.getenv("DATA_PATH", "/opt/aifinancialcrime")
        if not os.path.exists(data_path):
            data_path = "/"
        usage = shutil.disk_usage(data_path)
        used_pct = usage.used / usage.total * 100
        free_gb = usage.free / 1024**3
        status_str = "ok"
        if used_pct > 90:
            status_str = "error"
        elif used_pct > 75:
            status_str = "degraded"
        return ComponentStatus(
            status=status_str,
            detail=f"used={used_pct:.1f}% free={free_gb:.1f}GB path={data_path}",
        )
    except Exception as e:
        return ComponentStatus(status="error", detail=str(e))


def _check_memory() -> ComponentStatus:
    """Check available system memory (Raspberry Pi 16GB)."""
    try:
        with open("/proc/meminfo") as f:
            lines = {k.strip(":"): int(v.split()[0])
                     for line in f for k, v in [line.split(":", 1)]
                     if ":" in line}
        total_mb = lines.get("MemTotal", 0) / 1024
        avail_mb = lines.get("MemAvailable", 0) / 1024
        used_pct = (1 - avail_mb / total_mb) * 100 if total_mb else 0
        status_str = "ok"
        if used_pct > 90:
            status_str = "error"
        elif used_pct > 75:
            status_str = "degraded"
        return ComponentStatus(
            status=status_str,
            detail=f"used={used_pct:.1f}% avail={avail_mb:.0f}MB total={total_mb:.0f}MB",
        )
    except Exception as e:
        return ComponentStatus(status="error", detail=str(e))


def _check_cpu_temp() -> ComponentStatus:
    """Read Raspberry Pi CPU temperature from thermal zone."""
    try:
        temp_path = "/sys/class/thermal/thermal_zone0/temp"
        if not os.path.exists(temp_path):
            return ComponentStatus(status="ok", detail="no thermal sensor (non-Pi)")
        with open(temp_path) as f:
            temp_c = int(f.read().strip()) / 1000
        status_str = "ok"
        if temp_c > 80:
            status_str = "error"
        elif temp_c > 70:
            status_str = "degraded"
        return ComponentStatus(status=status_str, detail=f"cpu_temp={temp_c:.1f}°C")
    except Exception as e:
        return ComponentStatus(status="error", detail=str(e))


def _aggregate_status(components: dict[str, ComponentStatus]) -> str:
    statuses = [c.status for c in components.values()]
    if "error" in statuses:
        return "unhealthy"
    if "degraded" in statuses:
        return "degraded"
    return "healthy"


def _make_response(components: dict[str, ComponentStatus]) -> HealthResponse:
    return HealthResponse(
        status=_aggregate_status(components),
        version=_BUILD_VERSION,
        env=_ENV,
        uptime_seconds=round(time.monotonic() - _STARTUP_TS, 1),
        timestamp=datetime.now(timezone.utc).isoformat(),
        components=components,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", summary="Liveness probe")
async def liveness():
    """Always returns 200 if the process is alive. Used by systemd / k8s."""
    return {
        "status": "alive",
        "version": _BUILD_VERSION,
        "uptime_seconds": round(time.monotonic() - _STARTUP_TS, 1),
    }


@router.get("/ready", summary="Readiness probe", response_model=HealthResponse)
async def readiness(response: Response):
    """Checks DB + disk. Used by load-balancers before routing traffic."""
    components = {
        "database": await _check_db(),
        "disk": _check_disk(),
    }
    hr = _make_response(components)
    if hr.status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    logger.info("readiness_check", status=hr.status)
    return hr


@router.get("/db", summary="Database health", response_model=HealthResponse)
async def db_health(response: Response):
    components = {"database": await _check_db()}
    hr = _make_response(components)
    if hr.status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return hr


@router.get("/blockchain", summary="Blockchain API health", response_model=HealthResponse)
async def blockchain_health():
    components = {"blockstream_api": await _check_blockchain()}
    return _make_response(components)


@router.get("/system", summary="System resources (Pi)", response_model=HealthResponse)
async def system_health(response: Response):
    components = {
        "disk": _check_disk(),
        "memory": _check_memory(),
        "cpu_temperature": _check_cpu_temp(),
    }
    hr = _make_response(components)
    if hr.status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return hr


@router.get("/full", summary="Full health check", response_model=HealthResponse)
async def full_health(response: Response):
    """All components. For dashboards and manual inspection."""
    db_task = asyncio.create_task(_check_db())
    bc_task = asyncio.create_task(_check_blockchain())

    db_result, bc_result = await asyncio.gather(db_task, bc_task)

    components = {
        "database": db_result,
        "blockstream_api": bc_result,
        "disk": _check_disk(),
        "memory": _check_memory(),
        "cpu_temperature": _check_cpu_temp(),
    }
    hr = _make_response(components)
    if hr.status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    logger.info("full_health_check", status=hr.status, components={
        k: v.status for k, v in components.items()
    })
    return hr
