"""
Case Management API
src/api/cases.py

Endpunkte für das Opfer-Portal:

  Auth:
    POST /auth/register          — Registrierung
    POST /auth/login             — Login → JWT
    GET  /auth/me                — eigenes Profil

  Cases:
    POST /cases                  — neuen Fall anlegen
    GET  /cases                  — alle Fälle des Nutzers
    GET  /cases/{case_id}        — Fall-Details
    PATCH /cases/{case_id}       — Fall aktualisieren
    DELETE /cases/{case_id}      — Fall löschen

  Timeline / Actions:
    POST /cases/{case_id}/actions           — Aktion hinzufügen
    GET  /cases/{case_id}/actions           — Timeline abrufen
    PATCH /cases/{case_id}/actions/{id}     — Aktion aktualisieren
    DELETE /cases/{case_id}/actions/{id}    — Aktion löschen

  Dokumente:
    GET  /cases/{case_id}/documents         — Dokumente abrufen
    GET  /cases/{case_id}/documents/{id}    — Dokument herunterladen

  Kontakte:
    POST /cases/{case_id}/contacts          — Kontakt hinzufügen
    GET  /cases/{case_id}/contacts          — Kontakte abrufen
    PATCH /cases/{case_id}/contacts/{id}    — Kontakt aktualisieren

  Dashboard:
    GET  /dashboard                         — Übersicht alle Fälle
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["cases"])
security = HTTPBearer()

JWT_SECRET   = os.environ.get("JWT_SECRET", "change-in-production")
JWT_ALGO     = "HS256"
JWT_EXPIRE_H = 72   # 3 Tage
UPLOAD_DIR   = os.environ.get("UPLOAD_DIR", "/opt/aifinancialcrime/uploads")

os.makedirs(UPLOAD_DIR, exist_ok=True)


# =============================================================================
# Pydantic Models
# =============================================================================

# ── Auth ─────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    preferred_lang: str = Field(default="de", pattern="^(de|en)$")

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str

class UserProfile(BaseModel):
    user_id: str
    email: str
    full_name: Optional[str]
    preferred_lang: str
    is_verified: bool
    created_at: datetime

# ── Cases ─────────────────────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    fraud_txid: Optional[str] = None
    fraud_address: Optional[str] = None
    fraud_amount_btc: Optional[float] = None
    fraud_amount_eur: Optional[float] = None
    fraud_date: Optional[date] = None
    fraud_description: Optional[str] = None

class CaseUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    fraud_description: Optional[str] = None
    fraud_amount_eur: Optional[float] = None
    status: Optional[str] = Field(None, pattern="^(OPEN|PENDING|RESOLVED|CLOSED|ARCHIVED)$")

class CaseResponse(BaseModel):
    case_id: str
    title: str
    fraud_txid: Optional[str]
    fraud_address: Optional[str]
    fraud_amount_btc: Optional[float]
    fraud_amount_eur: Optional[float]
    fraud_date: Optional[date]
    fraud_description: Optional[str]
    status: str
    forensic_case_id: Optional[str]
    report_generated: bool
    freeze_request_sent: bool
    police_report_filed: bool
    lawyer_engaged: bool
    exchange_responded: bool
    pending_actions: int
    document_count: int
    last_action_title: Optional[str]
    last_action_date: Optional[date]
    days_since_update: Optional[int]
    created_at: datetime
    updated_at: datetime

# ── Actions ───────────────────────────────────────────────────────────────────

VALID_ACTION_TYPES = {
    "USER_POLICE_REPORT_FILED", "USER_FREEZE_REQUEST_SENT",
    "USER_LAWYER_CONTACTED", "USER_EXCHANGE_CONTACTED",
    "USER_BAFIN_CONTACTED", "USER_COURT_FILING",
    "USER_MEDIA_CONTACTED", "RESPONSE_POLICE",
    "RESPONSE_EXCHANGE", "RESPONSE_LAWYER",
    "RESPONSE_COURT", "RESPONSE_BAFIN",
    "STATUS_CHANGE", "NOTE",
}

class ActionCreate(BaseModel):
    action_type: str
    status: str = Field(default="DONE", pattern="^(DONE|PENDING|FAILED|CANCELLED)$")
    action_date: date = Field(default_factory=date.today)
    title: str = Field(..., min_length=2, max_length=300)
    description: Optional[str] = None
    reference_number: Optional[str] = None
    contact_name: Optional[str] = None
    contact_org: Optional[str] = None

    @field_validator("action_type")
    @classmethod
    def validate_action_type(cls, v):
        if v not in VALID_ACTION_TYPES:
            raise ValueError(f"Ungültiger action_type: {v}")
        return v

class ActionUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(DONE|PENDING|FAILED|CANCELLED)$")
    title: Optional[str] = Field(None, min_length=2, max_length=300)
    description: Optional[str] = None
    reference_number: Optional[str] = None
    contact_name: Optional[str] = None
    contact_org: Optional[str] = None

class ActionResponse(BaseModel):
    action_id: str
    action_type: str
    status: str
    action_date: date
    title: str
    description: Optional[str]
    reference_number: Optional[str]
    contact_name: Optional[str]
    contact_org: Optional[str]
    document_id: Optional[str]
    is_system: bool
    created_at: datetime

# ── Contacts ──────────────────────────────────────────────────────────────────

class ContactCreate(BaseModel):
    contact_type: str = Field(..., pattern="^(POLICE|EXCHANGE|LAWYER|BAFIN|COURT|MEDIATOR|OTHER)$")
    org_name: str = Field(..., min_length=2)
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    reference_number: Optional[str] = None
    notes: Optional[str] = None
    first_contact_date: Optional[date] = None

class ContactUpdate(BaseModel):
    contact_person: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    reference_number: Optional[str] = None
    notes: Optional[str] = None
    last_contact_date: Optional[date] = None

class ContactResponse(BaseModel):
    contact_id: str
    contact_type: str
    org_name: str
    contact_person: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    reference_number: Optional[str]
    notes: Optional[str]
    first_contact_date: Optional[date]
    last_contact_date: Optional[date]


# =============================================================================
# Auth Helpers
# =============================================================================

def _hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()

def _verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def _create_token(user_id: str, email: str) -> str:
    payload = {
        "sub":   user_id,
        "email": email,
        "iat":   datetime.now(timezone.utc),
        "exp":   datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_H),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token abgelaufen")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Ungültiger Token")


# =============================================================================
# Dependencies
# =============================================================================

def get_db():
    """DB-Connection Dependency — wird in main.py überschrieben."""
    raise NotImplementedError("get_db() muss in main.py implementiert werden")

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    conn = Depends(get_db),
) -> dict:
    """JWT validieren und User aus DB laden."""
    payload = _decode_token(credentials.credentials)
    user_id = payload.get("sub")

    with conn.cursor() as cur:
        cur.execute(
            "SELECT user_id, email, full_name, preferred_lang, is_active, "
            "is_verified, created_at FROM users WHERE user_id = %s",
            (user_id,)
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Benutzer nicht gefunden")
    if not row[4]:  # is_active
        raise HTTPException(status_code=403, detail="Account deaktiviert")

    return {
        "user_id": str(row[0]), "email": row[1],
        "full_name": row[2], "preferred_lang": row[3],
        "is_verified": row[5], "created_at": row[6],
    }

def _assert_case_owner(conn, case_id: str, user_id: str):
    """Stellt sicher dass der Fall dem aktuellen User gehört."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM user_cases WHERE case_id = %s AND user_id = %s",
            (case_id, user_id)
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Fall nicht gefunden")


# =============================================================================
# Auth Endpoints
# =============================================================================

@router.post("/auth/register", response_model=TokenResponse, status_code=201)
async def register(req: RegisterRequest, conn=Depends(get_db)):
    """Neuen Benutzer registrieren."""
    # E-Mail bereits vergeben?
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE email = %s", (req.email,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="E-Mail bereits registriert")

    user_id = str(uuid.uuid4())
    pw_hash = _hash_password(req.password)

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO users (user_id, email, password_hash, full_name, preferred_lang)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, req.email, pw_hash, req.full_name, req.preferred_lang))
    conn.commit()

    token = _create_token(user_id, req.email)
    logger.info(f"Neuer User registriert: {req.email}")
    return TokenResponse(access_token=token, user_id=user_id, email=req.email)


@router.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest, conn=Depends(get_db)):
    """Login — gibt JWT zurück."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT user_id, password_hash, is_active FROM users WHERE email = %s",
            (req.email,)
        )
        row = cur.fetchone()

    if not row or not _verify_password(req.password, row[1]):
        raise HTTPException(status_code=401, detail="E-Mail oder Passwort falsch")
    if not row[2]:
        raise HTTPException(status_code=403, detail="Account deaktiviert")

    # Last-login aktualisieren
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET last_login_at = NOW() WHERE user_id = %s", (row[0],)
        )
    conn.commit()

    token = _create_token(str(row[0]), req.email)
    return TokenResponse(access_token=token, user_id=str(row[0]), email=req.email)


@router.get("/auth/me", response_model=UserProfile)
async def get_me(user=Depends(get_current_user)):
    return UserProfile(**user)


# =============================================================================
# Case Endpoints
# =============================================================================

@router.post("/cases", response_model=CaseResponse, status_code=201)
async def create_case(
    req: CaseCreate,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Neuen Fall anlegen."""
    case_id = str(uuid.uuid4())

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO user_cases
                (case_id, user_id, title, fraud_txid, fraud_address,
                 fraud_amount_btc, fraud_amount_eur, fraud_date, fraud_description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            case_id, user["user_id"], req.title,
            req.fraud_txid, req.fraud_address,
            req.fraud_amount_btc, req.fraud_amount_eur,
            req.fraud_date, req.fraud_description,
        ))
    conn.commit()

    logger.info(f"Neuer Fall angelegt: {case_id} für User {user['user_id']}")
    return await get_case(case_id, user, conn)


@router.get("/cases", response_model=list[CaseResponse])
async def list_cases(
    user=Depends(get_current_user),
    conn=Depends(get_db),
    status_filter: Optional[str] = None,
):
    """Alle Fälle des eingeloggten Nutzers."""
    query = """
        SELECT case_id, title, fraud_txid, fraud_address,
               fraud_amount_btc, fraud_amount_eur, fraud_date, fraud_description,
               status, forensic_case_id,
               report_generated, freeze_request_sent, police_report_filed,
               lawyer_engaged, exchange_responded,
               pending_actions, document_count,
               last_action_title, last_action_date, days_since_update,
               created_at, updated_at
        FROM case_dashboard
        WHERE user_id = %s
    """
    params = [user["user_id"]]

    if status_filter:
        query += " AND status = %s"
        params.append(status_filter)

    query += " ORDER BY updated_at DESC"

    with conn.cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()

    return [_row_to_case(row) for row in rows]


@router.get("/cases/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: str,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Fall-Details abrufen."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT case_id, title, fraud_txid, fraud_address,
                   fraud_amount_btc, fraud_amount_eur, fraud_date, fraud_description,
                   status, forensic_case_id,
                   report_generated, freeze_request_sent, police_report_filed,
                   lawyer_engaged, exchange_responded,
                   pending_actions, document_count,
                   last_action_title, last_action_date, days_since_update,
                   created_at, updated_at
            FROM case_dashboard
            WHERE case_id = %s AND user_id = %s
        """, (case_id, user["user_id"]))
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Fall nicht gefunden")
    return _row_to_case(row)


@router.patch("/cases/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: str,
    req: CaseUpdate,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Fall aktualisieren."""
    _assert_case_owner(conn, case_id, user["user_id"])

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        return await get_case(case_id, user, conn)

    set_clause = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [case_id]

    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE user_cases SET {set_clause}, updated_at = NOW() WHERE case_id = %s",
            values
        )
    conn.commit()
    return await get_case(case_id, user, conn)


@router.delete("/cases/{case_id}", status_code=204)
async def delete_case(
    case_id: str,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Fall löschen (CASCADE auf alle Actions/Dokumente)."""
    _assert_case_owner(conn, case_id, user["user_id"])
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM user_cases WHERE case_id = %s AND user_id = %s",
            (case_id, user["user_id"])
        )
    conn.commit()


# =============================================================================
# Action / Timeline Endpoints
# =============================================================================

@router.post("/cases/{case_id}/actions", response_model=ActionResponse, status_code=201)
async def add_action(
    case_id: str,
    req: ActionCreate,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Aktion zur Timeline hinzufügen."""
    _assert_case_owner(conn, case_id, user["user_id"])

    action_id = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO case_actions
                (action_id, case_id, action_type, status, action_date,
                 title, description, reference_number, contact_name, contact_org,
                 is_system)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE)
        """, (
            action_id, case_id, req.action_type, req.status, req.action_date,
            req.title, req.description, req.reference_number,
            req.contact_name, req.contact_org,
        ))
        # Flags aktualisieren
        cur.execute("SELECT refresh_case_flags(%s)", (case_id,))
    conn.commit()

    return await _get_action(conn, action_id)


@router.get("/cases/{case_id}/actions", response_model=list[ActionResponse])
async def get_actions(
    case_id: str,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Vollständige Timeline eines Falls."""
    _assert_case_owner(conn, case_id, user["user_id"])

    with conn.cursor() as cur:
        cur.execute("""
            SELECT action_id, action_type, status, action_date,
                   title, description, reference_number,
                   contact_name, contact_org, document_id,
                   is_system, created_at
            FROM case_actions
            WHERE case_id = %s
            ORDER BY action_date DESC, created_at DESC
        """, (case_id,))
        rows = cur.fetchall()

    return [_row_to_action(r) for r in rows]


@router.patch("/cases/{case_id}/actions/{action_id}", response_model=ActionResponse)
async def update_action(
    case_id: str,
    action_id: str,
    req: ActionUpdate,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Aktion aktualisieren (z.B. Status von PENDING auf DONE)."""
    _assert_case_owner(conn, case_id, user["user_id"])

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        return await _get_action(conn, action_id)

    set_clause = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [action_id, case_id]

    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE case_actions SET {set_clause}, updated_at = NOW() "
            f"WHERE action_id = %s AND case_id = %s",
            values
        )
        cur.execute("SELECT refresh_case_flags(%s)", (case_id,))
    conn.commit()

    return await _get_action(conn, action_id)


@router.delete("/cases/{case_id}/actions/{action_id}", status_code=204)
async def delete_action(
    case_id: str,
    action_id: str,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Aktion löschen."""
    _assert_case_owner(conn, case_id, user["user_id"])
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM case_actions WHERE action_id = %s AND case_id = %s "
            "AND is_system = FALSE",  # System-Actions nicht löschbar
            (action_id, case_id)
        )
        cur.execute("SELECT refresh_case_flags(%s)", (case_id,))
    conn.commit()


# =============================================================================
# Contact Endpoints
# =============================================================================

@router.post("/cases/{case_id}/contacts", response_model=ContactResponse, status_code=201)
async def add_contact(
    case_id: str,
    req: ContactCreate,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    _assert_case_owner(conn, case_id, user["user_id"])
    contact_id = str(uuid.uuid4())

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO case_contacts
                (contact_id, case_id, contact_type, org_name, contact_person,
                 email, phone, address, reference_number, notes, first_contact_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            contact_id, case_id, req.contact_type, req.org_name,
            req.contact_person, req.email, req.phone, req.address,
            req.reference_number, req.notes, req.first_contact_date,
        ))
    conn.commit()
    return await _get_contact(conn, contact_id)


@router.get("/cases/{case_id}/contacts", response_model=list[ContactResponse])
async def get_contacts(
    case_id: str,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    _assert_case_owner(conn, case_id, user["user_id"])
    with conn.cursor() as cur:
        cur.execute("""
            SELECT contact_id, contact_type, org_name, contact_person,
                   email, phone, reference_number, notes,
                   first_contact_date, last_contact_date
            FROM case_contacts WHERE case_id = %s
            ORDER BY first_contact_date DESC NULLS LAST
        """, (case_id,))
        return [_row_to_contact(r) for r in cur.fetchall()]


@router.patch("/cases/{case_id}/contacts/{contact_id}", response_model=ContactResponse)
async def update_contact(
    case_id: str,
    contact_id: str,
    req: ContactUpdate,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    _assert_case_owner(conn, case_id, user["user_id"])
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if updates:
        set_clause = ", ".join(f"{k} = %s" for k in updates)
        values = list(updates.values()) + [contact_id, case_id]
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE case_contacts SET {set_clause} "
                f"WHERE contact_id = %s AND case_id = %s", values
            )
        conn.commit()
    return await _get_contact(conn, contact_id)


# =============================================================================
# Document Endpoints
# =============================================================================

@router.get("/cases/{case_id}/documents")
async def get_documents(
    case_id: str,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Alle Dokumente eines Falls."""
    _assert_case_owner(conn, case_id, user["user_id"])
    with conn.cursor() as cur:
        cur.execute("""
            SELECT document_id, doc_type, filename, file_size_bytes,
                   mime_type, title, exchange_name, is_generated, uploaded_at
            FROM case_documents WHERE case_id = %s
            ORDER BY uploaded_at DESC
        """, (case_id,))
        rows = cur.fetchall()

    return [
        {
            "document_id":    str(r[0]),
            "doc_type":       r[1],
            "filename":       r[2],
            "file_size_bytes": r[3],
            "mime_type":      r[4],
            "title":          r[5],
            "exchange_name":  r[6],
            "is_generated":   r[7],
            "uploaded_at":    r[8].isoformat() if r[8] else None,
        }
        for r in rows
    ]


@router.post("/cases/{case_id}/documents/upload", status_code=201)
async def upload_document(
    case_id: str,
    doc_type: str,
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Dokument hochladen (z.B. Polizei-Eingangsbestätigung als PDF/JPG)."""
    _assert_case_owner(conn, case_id, user["user_id"])

    # Datei speichern
    content = await file.read()
    sha256  = hashlib.sha256(content).hexdigest()
    doc_id  = str(uuid.uuid4())
    ext     = os.path.splitext(file.filename or "doc")[1] or ".bin"
    save_path = os.path.join(UPLOAD_DIR, f"{doc_id}{ext}")

    with open(save_path, "wb") as f:
        f.write(content)

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO case_documents
                (document_id, case_id, doc_type, filename, storage_path,
                 file_size_bytes, mime_type, sha256_hash, is_generated)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, FALSE)
        """, (
            doc_id, case_id, doc_type,
            file.filename, save_path, len(content),
            file.content_type, sha256,
        ))
    conn.commit()
    return {"document_id": doc_id, "filename": file.filename, "size": len(content)}


@router.get("/cases/{case_id}/documents/{document_id}/download")
async def download_document(
    case_id: str,
    document_id: str,
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Dokument herunterladen."""
    _assert_case_owner(conn, case_id, user["user_id"])
    with conn.cursor() as cur:
        cur.execute(
            "SELECT storage_path, filename, mime_type FROM case_documents "
            "WHERE document_id = %s AND case_id = %s",
            (document_id, case_id)
        )
        row = cur.fetchone()

    if not row or not os.path.exists(row[0]):
        raise HTTPException(status_code=404, detail="Dokument nicht gefunden")

    return FileResponse(
        path=row[0], filename=row[1],
        media_type=row[2] or "application/octet-stream"
    )


# =============================================================================
# Dashboard
# =============================================================================

@router.get("/dashboard")
async def get_dashboard(
    user=Depends(get_current_user),
    conn=Depends(get_db),
):
    """Übersicht aller Fälle + Statistiken."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*)                                        AS total_cases,
                COUNT(*) FILTER (WHERE status = 'OPEN')        AS open_cases,
                COUNT(*) FILTER (WHERE status = 'PENDING')     AS pending_cases,
                COUNT(*) FILTER (WHERE status = 'RESOLVED')    AS resolved_cases,
                SUM(fraud_amount_eur)                          AS total_loss_eur,
                SUM(fraud_amount_btc)                          AS total_loss_btc,
                COUNT(*) FILTER (WHERE pending_actions > 0)    AS cases_awaiting_response
            FROM case_dashboard WHERE user_id = %s
        """, (user["user_id"],))
        stats = cur.fetchone()

    cases = await list_cases(user=user, conn=conn)

    return {
        "user":   {"email": user["email"], "full_name": user["full_name"]},
        "stats":  {
            "total_cases":           stats[0] or 0,
            "open_cases":            stats[1] or 0,
            "pending_cases":         stats[2] or 0,
            "resolved_cases":        stats[3] or 0,
            "total_loss_eur":        float(stats[4]) if stats[4] else None,
            "total_loss_btc":        float(stats[5]) if stats[5] else None,
            "cases_awaiting_response": stats[6] or 0,
        },
        "cases":  cases,
    }


# =============================================================================
# Interne Hilfsfunktionen
# =============================================================================

def _row_to_case(row) -> CaseResponse:
    return CaseResponse(
        case_id=str(row[0]), title=row[1],
        fraud_txid=row[2], fraud_address=row[3],
        fraud_amount_btc=float(row[4]) if row[4] else None,
        fraud_amount_eur=float(row[5]) if row[5] else None,
        fraud_date=row[6], fraud_description=row[7],
        status=row[8], forensic_case_id=row[9],
        report_generated=row[10], freeze_request_sent=row[11],
        police_report_filed=row[12], lawyer_engaged=row[13],
        exchange_responded=row[14],
        pending_actions=row[15] or 0, document_count=row[16] or 0,
        last_action_title=row[17], last_action_date=row[18],
        days_since_update=int(row[19]) if row[19] is not None else None,
        created_at=row[20], updated_at=row[21],
    )

def _row_to_action(row) -> ActionResponse:
    return ActionResponse(
        action_id=str(row[0]), action_type=row[1], status=row[2],
        action_date=row[3], title=row[4], description=row[5],
        reference_number=row[6], contact_name=row[7], contact_org=row[8],
        document_id=str(row[9]) if row[9] else None,
        is_system=row[10], created_at=row[11],
    )

def _row_to_contact(row) -> ContactResponse:
    return ContactResponse(
        contact_id=str(row[0]), contact_type=row[1], org_name=row[2],
        contact_person=row[3], email=row[4], phone=row[5],
        reference_number=row[6], notes=row[7],
        first_contact_date=row[8], last_contact_date=row[9],
    )

async def _get_action(conn, action_id: str) -> ActionResponse:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT action_id, action_type, status, action_date,
                   title, description, reference_number,
                   contact_name, contact_org, document_id,
                   is_system, created_at
            FROM case_actions WHERE action_id = %s
        """, (action_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Aktion nicht gefunden")
    return _row_to_action(row)

async def _get_contact(conn, contact_id: str) -> ContactResponse:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT contact_id, contact_type, org_name, contact_person,
                   email, phone, reference_number, notes,
                   first_contact_date, last_contact_date
            FROM case_contacts WHERE contact_id = %s
        """, (contact_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Kontakt nicht gefunden")
    return _row_to_contact(row)
