"""
AIFinancialCrime — Prometheus Metrics
======================================
Exposes /metrics endpoint for Prometheus scraping.
Tracks investigation pipeline performance, attribution quality,
API request latency, and Raspberry Pi system metrics.

Setup in main.py:
    from src.core.metrics import setup_metrics, metrics
    setup_metrics(app)

    # In investigation pipeline:
    metrics.investigation_started()
    metrics.investigation_completed(duration_s=12.4, hop_count=7,
                                    attribution_hits=3, confidence_levels=["L1","L2","L2"])
    metrics.attribution_lookup(hit=True, source="local_db")
    metrics.peeling_chain_detected(depth=9)
    metrics.freeze_request_sent(exchange="Binance")
    metrics.report_generated(language="de")
"""

import os
import time
import asyncio
import platform
import shutil
from typing import Optional

from src.core.logging_config import get_logger

logger = get_logger("aifc.metrics")

# ---------------------------------------------------------------------------
# Optional prometheus_client import — graceful fallback if not installed
# ---------------------------------------------------------------------------
try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Info,
        make_asgi_app, CollectorRegistry, REGISTRY,
        multiprocess,
    )
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client_not_installed",
                   detail="pip install prometheus-client to enable /metrics")


# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

class AIFCMetrics:
    """
    Central metrics registry for AIFinancialCrime.

    All metrics use the `aifc_` prefix for Prometheus namespacing.
    """

    def __init__(self):
        if not _PROMETHEUS_AVAILABLE:
            self._available = False
            return
        self._available = True

        # -- Investigations --------------------------------------------------
        self.investigations_total = Counter(
            "aifc_investigations_total",
            "Total number of investigations started",
            ["status"],  # started | completed | failed
        )
        self.investigation_duration = Histogram(
            "aifc_investigation_duration_seconds",
            "Time to complete a full investigation pipeline",
            buckets=[1, 2, 5, 10, 20, 30, 60, 120],
        )
        self.investigation_hop_count = Histogram(
            "aifc_investigation_hop_count",
            "Number of hops traced per investigation",
            buckets=[1, 2, 3, 5, 8, 12, 20, 50],
        )

        # -- Attribution -----------------------------------------------------
        self.attribution_lookups_total = Counter(
            "aifc_attribution_lookups_total",
            "Attribution DB lookups",
            ["result", "source"],  # hit/miss, local_db/blockstream/manual
        )
        self.attribution_hit_rate = Gauge(
            "aifc_attribution_hit_rate",
            "Rolling attribution hit rate (0–1)",
        )
        self._attr_total = 0
        self._attr_hits = 0

        # -- Confidence Levels -----------------------------------------------
        self.confidence_level_total = Counter(
            "aifc_confidence_level_total",
            "Confidence levels assigned across all hops",
            ["level"],  # L1 | L2 | L3 | L4
        )

        # -- Peeling Chains --------------------------------------------------
        self.peeling_chains_detected = Counter(
            "aifc_peeling_chains_detected_total",
            "Peeling chains detected",
        )
        self.peeling_chain_depth = Histogram(
            "aifc_peeling_chain_depth",
            "Depth of detected peeling chains",
            buckets=[2, 3, 5, 8, 12, 20, 50],
        )

        # -- Serial Actor ----------------------------------------------------
        self.serial_actor_matches = Counter(
            "aifc_serial_actor_matches_total",
            "Serial actor cross-case address matches found",
        )

        # -- Reports ---------------------------------------------------------
        self.reports_generated_total = Counter(
            "aifc_reports_generated_total",
            "PDF reports generated",
            ["language"],  # de | en
        )
        self.report_generation_duration = Histogram(
            "aifc_report_generation_duration_seconds",
            "Time to generate a PDF report",
            buckets=[0.5, 1, 2, 5, 10, 20],
        )

        # -- Freeze Requests -------------------------------------------------
        self.freeze_requests_total = Counter(
            "aifc_freeze_requests_total",
            "Exchange freeze requests generated",
            ["exchange"],
        )

        # -- API -------------------------------------------------------------
        self.api_requests_total = Counter(
            "aifc_api_requests_total",
            "API requests received",
            ["method", "endpoint", "status_code"],
        )
        self.api_request_duration = Histogram(
            "aifc_api_request_duration_seconds",
            "API request latency",
            ["method", "endpoint"],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5],
        )
        self.api_errors_total = Counter(
            "aifc_api_errors_total",
            "API errors (4xx + 5xx)",
            ["endpoint", "error_type"],
        )

        # -- Bulk Import -----------------------------------------------------
        self.bulk_import_addresses = Counter(
            "aifc_bulk_import_addresses_total",
            "Attribution addresses imported via bulk ingest",
            ["source"],  # walletexplorer | arkham | oxt | ofac | manual
        )
        self.bulk_import_duration = Histogram(
            "aifc_bulk_import_duration_seconds",
            "Duration of bulk import runs",
            ["source"],
            buckets=[1, 5, 10, 30, 60, 120, 300, 600],
        )

        # -- Blockstream API -------------------------------------------------
        self.blockstream_requests_total = Counter(
            "aifc_blockstream_requests_total",
            "Requests to Blockstream API",
            ["endpoint", "status"],  # ok | error | timeout
        )
        self.blockstream_latency = Histogram(
            "aifc_blockstream_latency_seconds",
            "Blockstream API response latency",
            buckets=[0.1, 0.25, 0.5, 1, 2, 5, 10],
        )

        # -- System (Raspberry Pi) ------------------------------------------
        self.system_disk_used_bytes = Gauge(
            "aifc_system_disk_used_bytes",
            "Disk used bytes on data path",
        )
        self.system_disk_free_bytes = Gauge(
            "aifc_system_disk_free_bytes",
            "Disk free bytes on data path",
        )
        self.system_memory_used_bytes = Gauge(
            "aifc_system_memory_used_bytes",
            "Memory used bytes",
        )
        self.system_memory_total_bytes = Gauge(
            "aifc_system_memory_total_bytes",
            "Total system memory bytes",
        )
        self.system_cpu_temp_celsius = Gauge(
            "aifc_system_cpu_temp_celsius",
            "Raspberry Pi CPU temperature in Celsius",
        )

        # -- Build Info ------------------------------------------------------
        self.build_info = Info(
            "aifc_build",
            "Build information",
        )
        self.build_info.info({
            "version": os.getenv("AIFC_VERSION", "dev"),
            "env": os.getenv("AIFC_ENV", "production"),
            "python": platform.python_version(),
        })

    # -----------------------------------------------------------------------
    # Convenience helpers (no-op if prometheus not available)
    # -----------------------------------------------------------------------

    def investigation_started(self):
        if not self._available:
            return
        self.investigations_total.labels(status="started").inc()

    def investigation_completed(
        self,
        duration_s: float,
        hop_count: int = 0,
        attribution_hits: int = 0,
        confidence_levels: list[str] = None,
        serial_matches: int = 0,
    ):
        if not self._available:
            return
        self.investigations_total.labels(status="completed").inc()
        self.investigation_duration.observe(duration_s)
        if hop_count:
            self.investigation_hop_count.observe(hop_count)
        for lvl in (confidence_levels or []):
            self.confidence_level_total.labels(level=lvl).inc()
        if serial_matches:
            self.serial_actor_matches.inc(serial_matches)

    def investigation_failed(self, error_type: str = "unknown"):
        if not self._available:
            return
        self.investigations_total.labels(status="failed").inc()

    def attribution_lookup(self, hit: bool, source: str = "local_db"):
        if not self._available:
            return
        result = "hit" if hit else "miss"
        self.attribution_lookups_total.labels(result=result, source=source).inc()
        self._attr_total += 1
        if hit:
            self._attr_hits += 1
        if self._attr_total > 0:
            self.attribution_hit_rate.set(self._attr_hits / self._attr_total)

    def peeling_chain_detected(self, depth: int):
        if not self._available:
            return
        self.peeling_chains_detected.inc()
        self.peeling_chain_depth.observe(depth)

    def report_generated(self, language: str = "de", duration_s: float = 0):
        if not self._available:
            return
        self.reports_generated_total.labels(language=language).inc()
        if duration_s:
            self.report_generation_duration.observe(duration_s)

    def freeze_request_sent(self, exchange: str):
        if not self._available:
            return
        self.freeze_requests_total.labels(exchange=exchange.lower()).inc()

    def bulk_import_completed(self, source: str, count: int, duration_s: float):
        if not self._available:
            return
        self.bulk_import_addresses.labels(source=source).inc(count)
        self.bulk_import_duration.labels(source=source).observe(duration_s)

    def blockstream_request(self, endpoint: str, status: str, latency_s: float):
        if not self._available:
            return
        self.blockstream_requests_total.labels(endpoint=endpoint, status=status).inc()
        self.blockstream_latency.observe(latency_s)

    def collect_system_metrics(self):
        """Call periodically (e.g. every 30s) to update system gauges."""
        if not self._available:
            return
        try:
            data_path = os.getenv("DATA_PATH", "/opt/aifinancialcrime")
            if not os.path.exists(data_path):
                data_path = "/"
            usage = shutil.disk_usage(data_path)
            self.system_disk_used_bytes.set(usage.used)
            self.system_disk_free_bytes.set(usage.free)
        except Exception:
            pass

        try:
            with open("/proc/meminfo") as f:
                lines = {k.strip(":"): int(v.split()[0])
                         for line in f for k, v in [line.split(":", 1)]
                         if ":" in line}
            total = lines.get("MemTotal", 0) * 1024
            avail = lines.get("MemAvailable", 0) * 1024
            self.system_memory_total_bytes.set(total)
            self.system_memory_used_bytes.set(total - avail)
        except Exception:
            pass

        try:
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                temp_c = int(f.read().strip()) / 1000
            self.system_cpu_temp_celsius.set(temp_c)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

metrics = AIFCMetrics()


# ---------------------------------------------------------------------------
# FastAPI integration
# ---------------------------------------------------------------------------

def setup_metrics(app) -> None:
    """
    Mount Prometheus /metrics endpoint and register middleware.

    Call in main.py after app creation:
        setup_metrics(app)
    """
    if not _PROMETHEUS_AVAILABLE:
        logger.warning("metrics_endpoint_disabled",
                       detail="prometheus_client not installed")
        return

    # Mount /metrics
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    # Background system metrics collector
    import asyncio

    @app.on_event("startup")
    async def start_system_collector():
        async def _collect_loop():
            while True:
                metrics.collect_system_metrics()
                await asyncio.sleep(30)
        asyncio.create_task(_collect_loop())

    # Request metrics middleware
    @app.middleware("http")
    async def metrics_middleware(request, call_next):
        t0 = time.monotonic()
        response = await call_next(request)
        elapsed = time.monotonic() - t0

        path = request.url.path
        # Normalize parametric paths for cardinality control
        for prefix in ["/api/investigations/", "/api/cases/", "/api/documents/"]:
            if path.startswith(prefix):
                path = prefix + "{id}"
                break

        metrics.api_requests_total.labels(
            method=request.method,
            endpoint=path,
            status_code=str(response.status_code),
        ).inc()
        metrics.api_request_duration.labels(
            method=request.method,
            endpoint=path,
        ).observe(elapsed)

        if response.status_code >= 400:
            metrics.api_errors_total.labels(
                endpoint=path,
                error_type=f"http_{response.status_code}",
            ).inc()

        return response

    logger.info("metrics_endpoint_mounted", path="/metrics")
