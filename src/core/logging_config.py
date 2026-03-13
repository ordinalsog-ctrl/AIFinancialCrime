"""
AIFinancialCrime — Structured Logging
======================================
JSON-structured logging with correlation IDs, log levels, and
per-investigation context binding.

Usage:
    from src.core.logging_config import get_logger, bind_investigation

    logger = get_logger(__name__)
    logger.info("hop_traced", txid=txid, hop=3, confidence="L2")

    # Bind investigation context for all subsequent log calls:
    with bind_investigation("INV-2025-001"):
        logger.warning("peeling_chain_detected", depth=12)
"""

import logging
import sys
import time
import uuid
import json
import traceback
from contextvars import ContextVar
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from enum import Enum

# ---------------------------------------------------------------------------
# Context Variables (per-request, per-investigation)
# ---------------------------------------------------------------------------

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_investigation_id: ContextVar[str] = ContextVar("investigation_id", default="")
_api_key_id: ContextVar[str] = ContextVar("api_key_id", default="")


class bind_investigation:
    """Context manager to bind investigation metadata to all log calls."""

    def __init__(self, investigation_id: str, correlation_id: str = "", api_key_id: str = ""):
        self.inv_id = investigation_id
        self.corr_id = correlation_id or str(uuid.uuid4())[:8]
        self.key_id = api_key_id
        self._tokens = []

    def __enter__(self):
        self._tokens = [
            _investigation_id.set(self.inv_id),
            _correlation_id.set(self.corr_id),
            _api_key_id.set(self.key_id),
        ]
        return self

    def __exit__(self, *_):
        for token in self._tokens:
            token.var.reset(token)


def set_correlation_id(cid: str = "") -> str:
    """Set (or generate) a correlation ID for the current request context."""
    cid = cid or str(uuid.uuid4())[:12]
    _correlation_id.set(cid)
    return cid


# ---------------------------------------------------------------------------
# Log Levels
# ---------------------------------------------------------------------------

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# JSON Formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """
    Renders every log record as a single-line JSON object.

    Fields always present:
        ts          — ISO-8601 UTC timestamp
        level       — DEBUG / INFO / WARNING / ERROR / CRITICAL
        logger      — dotted module name
        event       — the log message (first positional arg)
        correlation_id
        investigation_id
        api_key_id

    Extra keyword args passed via logger.info("event", key=val) are
    merged at the top level (not nested).
    """

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }

        # Context vars
        corr = _correlation_id.get("")
        inv = _investigation_id.get("")
        key = _api_key_id.get("")
        if corr:
            doc["correlation_id"] = corr
        if inv:
            doc["investigation_id"] = inv
        if key:
            doc["api_key_id"] = key

        # Extra structured fields attached via LoggerAdapter
        if hasattr(record, "extra_fields"):
            doc.update(record.extra_fields)

        # Exception info
        if record.exc_info:
            doc["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        return json.dumps(doc, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Structured Logger Adapter
# ---------------------------------------------------------------------------

class StructuredLogger(logging.LoggerAdapter):
    """
    Extends standard Logger with structured keyword arguments.

    logger.info("hop_traced", txid="abc", hop=3)
    → {"event": "hop_traced", "txid": "abc", "hop": 3, ...}
    """

    def log(self, level: int, msg: str, *args, **kwargs):
        extra_fields = {k: v for k, v in kwargs.items()
                        if k not in ("exc_info", "stack_info", "stacklevel", "extra")}
        clean_kwargs = {k: v for k, v in kwargs.items()
                        if k in ("exc_info", "stack_info", "stacklevel")}
        if self.isEnabledFor(level):
            msg, kwargs2 = self.process(msg, {})
            record = self.logger.makeRecord(
                self.logger.name, level, "(unknown)", 0, msg, args, None
            )
            record.extra_fields = extra_fields  # type: ignore[attr-defined]
            self.logger.handle(record)

    def debug(self, msg, *args, **kwargs):
        self.log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.log(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.log(logging.CRITICAL, msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        kwargs.setdefault("exc_info", True)
        self.error(msg, *args, **kwargs)

    def process(self, msg, kwargs):
        return msg, kwargs


# ---------------------------------------------------------------------------
# Setup & Factory
# ---------------------------------------------------------------------------

_configured = False


def configure_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    pretty: bool = False,
) -> None:
    """
    Call once at application startup (e.g. in main.py lifespan).

    Args:
        level:    Minimum log level (DEBUG / INFO / WARNING / ERROR).
        log_file: Optional path — if set, logs are ALSO written to file.
        pretty:   If True, use human-readable format (dev mode only).
    """
    global _configured

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove default handlers
    root.handlers.clear()

    if pretty:
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
    else:
        fmt = JSONFormatter()

    # Stdout handler
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    # Optional file handler
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(JSONFormatter())  # always JSON in file
        root.addHandler(fh)

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "httpx", "httpcore", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> StructuredLogger:
    """Return a StructuredLogger for the given module name."""
    if not _configured:
        configure_logging()  # safe default
    base = logging.getLogger(name)
    return StructuredLogger(base, extra={})


# ---------------------------------------------------------------------------
# Request-scoped Middleware helper (for FastAPI)
# ---------------------------------------------------------------------------

async def logging_middleware(request, call_next):
    """
    FastAPI middleware: assigns correlation ID, logs request + response.

    Add to main.py:
        app.middleware("http")(logging_middleware)
    """
    import time as _time

    cid = request.headers.get("X-Correlation-ID") or set_correlation_id()
    logger = get_logger("aifc.http")

    t0 = _time.monotonic()
    logger.info(
        "request_received",
        method=request.method,
        path=request.url.path,
        correlation_id=cid,
    )

    response = await call_next(request)
    elapsed_ms = round((_time.monotonic() - t0) * 1000, 1)

    level = "warning" if response.status_code >= 400 else "info"
    getattr(logger, level)(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        elapsed_ms=elapsed_ms,
        correlation_id=cid,
    )

    response.headers["X-Correlation-ID"] = cid
    return response
