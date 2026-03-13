"""
Auth & Rate Limiting Middleware

Two auth paths, one middleware layer:
  - API Key  → B2B, machines, CLI tools (Header: X-API-Key)
  - JWT      → Web UI, private users (Header: Authorization: Bearer <token>)

Rate limiting:
  - Per API Key: tier-based limits (Free / Pro / Enterprise)
  - Per IP:      abuse protection, independent of key

Tier limits (requests per day):
  FREE:       10  fraud-reports,  100 other endpoints
  PRO:       100  fraud-reports, 1000 other endpoints
  ENTERPRISE: unlimited (soft limit 10000 for monitoring)

Storage: PostgreSQL (api_keys table) + in-memory counter cache
No Redis required — suitable for single-server deployment.
Swap to Redis later for horizontal scaling (one line change).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tiers & Limits
# ---------------------------------------------------------------------------

class Tier(str, Enum):
    FREE       = "FREE"
    PRO        = "PRO"
    ENTERPRISE = "ENTERPRISE"


@dataclass
class TierLimits:
    fraud_reports_per_day: int
    other_requests_per_day: int
    ip_requests_per_minute: int = 30


TIER_LIMITS: dict[Tier, TierLimits] = {
    Tier.FREE:       TierLimits(fraud_reports_per_day=10,    other_requests_per_day=100,  ip_requests_per_minute=20),
    Tier.PRO:        TierLimits(fraud_reports_per_day=100,   other_requests_per_day=1000, ip_requests_per_minute=60),
    Tier.ENTERPRISE: TierLimits(fraud_reports_per_day=10000, other_requests_per_day=50000, ip_requests_per_minute=300),
}

# Endpoints that count as "fraud_report" (expensive)
HEAVY_ENDPOINTS = {"/intel/fraud-report"}

JWT_SECRET  = os.environ.get("JWT_SECRET", "change-me-in-production-use-env-var")
JWT_ALGO    = "HS256"
JWT_TTL_H   = 24


# ---------------------------------------------------------------------------
# API Key model
# ---------------------------------------------------------------------------

@dataclass
class ApiKeyRecord:
    key_id: str
    key_hash: str          # SHA-256 of the raw key — never store raw
    owner_name: str
    owner_email: str
    tier: Tier
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: Optional[datetime] = None
    notes: str = ""

    def check(self, raw_key: str) -> bool:
        """Constant-time comparison against stored hash."""
        incoming_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return hmac.compare_digest(self.key_hash, incoming_hash)

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def generate() -> str:
        """Generate a cryptographically secure API key."""
        return f"afc_{secrets.token_urlsafe(32)}"


# ---------------------------------------------------------------------------
# In-memory rate limit counter
# (Replace _store with Redis client for horizontal scaling)
# ---------------------------------------------------------------------------

class RateLimitStore:
    """
    In-memory sliding window counter.
    key   → (count, window_start_ts)
    Thread-safe for single-process FastAPI (asyncio).
    """

    def __init__(self):
        self._data: dict[str, tuple[int, float]] = {}

    def check_and_increment(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int, int]:
        """
        Returns (allowed, current_count, retry_after_seconds).
        allowed=False means limit exceeded.
        """
        now = time.time()
        count, window_start = self._data.get(key, (0, now))

        # Reset window if expired
        if now - window_start >= window_seconds:
            count = 0
            window_start = now

        if count >= limit:
            retry_after = int(window_seconds - (now - window_start)) + 1
            return False, count, retry_after

        self._data[key] = (count + 1, window_start)
        return True, count + 1, 0

    def cleanup(self, max_age_seconds: int = 86400):
        """Evict stale entries — call periodically."""
        now = time.time()
        self._data = {
            k: v for k, v in self._data.items()
            if now - v[1] < max_age_seconds
        }


_rate_store = RateLimitStore()


# ---------------------------------------------------------------------------
# API Key repository (PostgreSQL)
# ---------------------------------------------------------------------------

class ApiKeyRepository:
    """
    Persists API keys in PostgreSQL.
    Keys are stored as SHA-256 hashes — raw key shown only once at creation.
    """

    CREATE_SQL = """
        INSERT INTO api_keys
            (key_id, key_hash, owner_name, owner_email, tier, is_active, notes, created_at)
        VALUES
            (%(key_id)s, %(key_hash)s, %(owner_name)s, %(owner_email)s,
             %(tier)s, %(is_active)s, %(notes)s, NOW())
        RETURNING key_id;
    """

    LOOKUP_SQL = """
        SELECT key_id, key_hash, owner_name, owner_email,
               tier, is_active, created_at, last_used_at, notes
        FROM api_keys
        WHERE key_id = %s AND is_active = TRUE;
    """

    UPDATE_LAST_USED_SQL = """
        UPDATE api_keys SET last_used_at = NOW() WHERE key_id = %s;
    """

    DEACTIVATE_SQL = """
        UPDATE api_keys SET is_active = FALSE WHERE key_id = %s;
    """

    def __init__(self, conn):
        self._conn = conn

    def create(
        self,
        owner_name: str,
        owner_email: str,
        tier: Tier = Tier.FREE,
        notes: str = "",
    ) -> tuple[str, str]:
        """
        Create a new API key.
        Returns (raw_key, key_id) — raw_key shown only once, never stored.
        """
        raw_key = ApiKeyRecord.generate()
        key_id  = f"kid_{secrets.token_hex(8)}"
        key_hash = ApiKeyRecord.hash_key(raw_key)

        with self._conn.cursor() as cur:
            cur.execute(self.CREATE_SQL, {
                "key_id":      key_id,
                "key_hash":    key_hash,
                "owner_name":  owner_name,
                "owner_email": owner_email,
                "tier":        tier.value,
                "is_active":   True,
                "notes":       notes,
            })
        self._conn.commit()
        return raw_key, key_id

    def lookup(self, key_id: str) -> Optional[ApiKeyRecord]:
        with self._conn.cursor() as cur:
            cur.execute(self.LOOKUP_SQL, (key_id,))
            row = cur.fetchone()
        if not row:
            return None
        return ApiKeyRecord(
            key_id=row[0], key_hash=row[1],
            owner_name=row[2], owner_email=row[3],
            tier=Tier(row[4]), is_active=row[5],
            created_at=row[6], last_used_at=row[7], notes=row[8] or "",
        )

    def touch(self, key_id: str):
        with self._conn.cursor() as cur:
            cur.execute(self.UPDATE_LAST_USED_SQL, (key_id,))
        self._conn.commit()

    def deactivate(self, key_id: str):
        with self._conn.cursor() as cur:
            cur.execute(self.DEACTIVATE_SQL, (key_id,))
        self._conn.commit()


# ---------------------------------------------------------------------------
# JWT helpers (no external library — pure stdlib)
# ---------------------------------------------------------------------------

import base64
import struct


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def create_jwt(
    subject: str,
    email: str,
    tier: Tier,
    ttl_hours: int = JWT_TTL_H,
) -> str:
    """Create a signed JWT. No external library required."""
    now = int(datetime.now(timezone.utc).timestamp())
    header  = _b64url_encode(json.dumps({"alg": JWT_ALGO, "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps({
        "sub":   subject,
        "email": email,
        "tier":  tier.value,
        "iat":   now,
        "exp":   now + ttl_hours * 3600,
    }).encode())
    signing_input = f"{header}.{payload}"
    sig = hmac.new(
        JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def verify_jwt(token: str) -> Optional[dict]:
    """
    Verify JWT signature and expiry.
    Returns payload dict or None if invalid.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256
        ).digest()
        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if payload.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Authenticated principal
# ---------------------------------------------------------------------------

@dataclass
class AuthPrincipal:
    """Unified auth result — same shape for API Key and JWT."""
    identity: str       # key_id or JWT subject
    email: str
    tier: Tier
    auth_method: str    # "api_key" or "jwt"
    key_id: Optional[str] = None


# ---------------------------------------------------------------------------
# FastAPI security schemes
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer_scheme  = HTTPBearer(auto_error=False)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(
    identity: str,
    ip: str,
    tier: Tier,
    endpoint: str,
) -> None:
    """
    Enforce two independent rate limits:
      1. Per identity (API key or JWT subject) — daily window
      2. Per IP — per-minute window
    Raises HTTP 429 if either limit is exceeded.
    """
    limits = TIER_LIMITS[tier]
    is_heavy = any(endpoint.startswith(h) for h in HEAVY_ENDPOINTS)

    # ── Identity limit (daily) ────────────────────────────────────────────
    limit = limits.fraud_reports_per_day if is_heavy else limits.other_requests_per_day
    allowed, count, retry = _rate_store.check_and_increment(
        key=f"id:{identity}:{'heavy' if is_heavy else 'light'}",
        limit=limit,
        window_seconds=86400,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error":       "rate_limit_exceeded",
                "limit_type":  "daily_per_key",
                "limit":       limit,
                "tier":        tier.value,
                "retry_after": retry,
                "message":     f"Daily limit of {limit} requests exceeded for tier {tier.value}. "
                               f"Retry after {retry}s or upgrade your tier.",
            },
            headers={"Retry-After": str(retry)},
        )

    # ── IP limit (per minute) ─────────────────────────────────────────────
    ip_allowed, ip_count, ip_retry = _rate_store.check_and_increment(
        key=f"ip:{ip}",
        limit=limits.ip_requests_per_minute,
        window_seconds=60,
    )
    if not ip_allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error":       "rate_limit_exceeded",
                "limit_type":  "per_minute_per_ip",
                "limit":       limits.ip_requests_per_minute,
                "retry_after": ip_retry,
                "message":     f"Too many requests from this IP. "
                               f"Retry after {ip_retry}s.",
            },
            headers={"Retry-After": str(ip_retry)},
        )


# ---------------------------------------------------------------------------
# Main dependency — use in any FastAPI endpoint
# ---------------------------------------------------------------------------

async def require_auth(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
) -> AuthPrincipal:
    """
    FastAPI dependency — validates API Key or JWT.
    Usage:
        @router.post("/intel/fraud-report")
        async def endpoint(principal: AuthPrincipal = Depends(require_auth)):
            ...
    """
    ip = _get_client_ip(request)
    principal: Optional[AuthPrincipal] = None

    # ── Try API Key ───────────────────────────────────────────────────────
    if api_key:
        principal = await _validate_api_key(api_key, request)

    # ── Try JWT Bearer ────────────────────────────────────────────────────
    elif bearer:
        principal = _validate_jwt(bearer.credentials)

    if not principal:
        raise HTTPException(
            status_code=401,
            detail={
                "error":   "unauthorized",
                "message": "Provide a valid API key (X-API-Key header) "
                           "or Bearer token (Authorization header).",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Rate limiting ─────────────────────────────────────────────────────
    _enforce_rate_limit(
        identity=principal.identity,
        ip=ip,
        tier=principal.tier,
        endpoint=request.url.path,
    )

    return principal


async def _validate_api_key(raw_key: str, request: Request) -> Optional[AuthPrincipal]:
    """
    Validate API key against database.
    Key format: afc_{key_id}_{secret}
    We derive key_id from the prefix to avoid full-table scan.
    """
    try:
        # Extract key_id prefix for DB lookup (first 20 chars after afc_)
        # Format: afc_<urlsafe_base64_32_bytes>
        # We use first 16 chars of the key as a lookup prefix stored separately
        # For simplicity: hash the full key and scan active keys
        # Production: store key_prefix separately for O(1) lookup
        conn = getattr(request.state, "db", None)
        if conn is None:
            # Fallback: check environment-defined master key (dev/test only)
            master_key = os.environ.get("AFC_MASTER_KEY")
            if master_key and hmac.compare_digest(raw_key, master_key):
                return AuthPrincipal(
                    identity="master",
                    email="admin@aifinancialcrime.com",
                    tier=Tier.ENTERPRISE,
                    auth_method="api_key",
                    key_id="master",
                )
            return None

        repo = ApiKeyRepository(conn)
        # In production: store key_prefix in DB for efficient lookup
        # Here: derive key_id from key (key embeds key_id after prefix)
        # Real format: afc_{key_id}_{secret} — parse key_id from key
        parts = raw_key.split("_", 2)
        if len(parts) < 2:
            return None
        # For now: full hash lookup (works for small key sets)
        key_hash = ApiKeyRecord.hash_key(raw_key)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key_id, owner_name, owner_email, tier FROM api_keys "
                "WHERE key_hash = %s AND is_active = TRUE",
                (key_hash,)
            )
            row = cur.fetchone()
        if not row:
            return None
        repo.touch(row[0])
        return AuthPrincipal(
            identity=row[0], email=row[2],
            tier=Tier(row[3]), auth_method="api_key", key_id=row[0],
        )
    except Exception as e:
        logger.warning(f"API key validation error: {e}")
        return None


def _validate_jwt(token: str) -> Optional[AuthPrincipal]:
    payload = verify_jwt(token)
    if not payload:
        return None
    return AuthPrincipal(
        identity=payload["sub"],
        email=payload.get("email", ""),
        tier=Tier(payload.get("tier", Tier.FREE.value)),
        auth_method="jwt",
    )


# ---------------------------------------------------------------------------
# Optional: auth-free health check dependency
# ---------------------------------------------------------------------------

async def optional_auth(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
) -> Optional[AuthPrincipal]:
    """Like require_auth but returns None instead of 401. For public endpoints."""
    try:
        return await require_auth(request, api_key, bearer)
    except HTTPException:
        return None
