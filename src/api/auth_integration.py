"""
Auth integration — so wird auth.py in fraud_report.py eingebunden.
Nur die geänderten Stellen, kein vollständiger File-Replace.

Änderungen an src/api/fraud_report.py:
  1. Import ergänzen
  2. Jeden Router-Endpoint um Depends(require_auth) erweitern
  3. Rate-Limit-Header in Response setzen
"""

# ── 1. Import (oben in fraud_report.py ergänzen) ─────────────────────────

from src.api.auth import AuthPrincipal, require_auth, TIER_LIMITS

# ── 2. Endpoint — vorher ─────────────────────────────────────────────────

# @router.post("/intel/fraud-report", response_model=FraudReportResponse)
# async def create_fraud_report(
#     request: FraudReportRequest,
#     db=Depends(get_db),
# ):

# ── 2. Endpoint — nachher ─────────────────────────────────────────────────

from fastapi import Depends
from fastapi.responses import JSONResponse

# Beispiel für den Haupt-Endpoint:
#
# @router.post("/intel/fraud-report", response_model=FraudReportResponse)
# async def create_fraud_report(
#     request: FraudReportRequest,
#     db=Depends(get_db),
#     principal: AuthPrincipal = Depends(require_auth),   # ← NEU
# ):
#     # Rate-Limit-Info als Response-Header (optional aber gut für Clients)
#     limits = TIER_LIMITS[principal.tier]
#     headers = {
#         "X-RateLimit-Tier":            principal.tier.value,
#         "X-RateLimit-Limit-Daily":     str(limits.fraud_reports_per_day),
#         "X-RateLimit-Auth-Method":     principal.auth_method,
#     }
#     # ... rest of existing logic unchanged ...
#     # return FraudReportResponse(...), headers

# ── 3. PDF-Download-Endpoint ─────────────────────────────────────────────

# @router.get("/intel/fraud-report/{case_id}/pdf")
# async def download_pdf(
#     case_id: str,
#     principal: AuthPrincipal = Depends(require_auth),   # ← NEU
# ):

# ── 4. Status-Endpoint (optional auth — öffentlich lesbar) ───────────────

# from src.api.auth import optional_auth
# @router.get("/intel/fraud-report/{case_id}/status")
# async def get_status(
#     case_id: str,
#     principal: Optional[AuthPrincipal] = Depends(optional_auth),  # ← NEU
# ):


# ── 5. Key-Management-Endpoints (Admin-only, separater Router) ───────────

from fastapi import APIRouter
from pydantic import BaseModel

admin_router = APIRouter(prefix="/admin", tags=["admin"])


class CreateKeyRequest(BaseModel):
    owner_name:  str
    owner_email: str
    tier:        str = "FREE"
    notes:       str = ""


class CreateKeyResponse(BaseModel):
    key_id:   str
    api_key:  str      # shown ONCE — never retrievable again
    tier:     str
    message:  str


# In main.py:
# from src.api.auth_integration import admin_router
# app.include_router(admin_router)
#
# @admin_router.post("/keys", response_model=CreateKeyResponse)
# async def create_api_key(
#     req: CreateKeyRequest,
#     principal: AuthPrincipal = Depends(require_auth),
#     db=Depends(get_db),
# ):
#     if principal.tier != Tier.ENTERPRISE or principal.identity != "master":
#         raise HTTPException(403, {"error": "admin_only"})
#     from src.api.auth import ApiKeyRepository, Tier
#     repo = ApiKeyRepository(db)
#     raw_key, key_id = repo.create(req.owner_name, req.owner_email, Tier(req.tier), req.notes)
#     return CreateKeyResponse(
#         key_id=key_id, api_key=raw_key, tier=req.tier,
#         message="Store this key securely — it will not be shown again."
#     )
