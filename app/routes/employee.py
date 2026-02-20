import datetime
import os
import secrets
import string
import uuid

from fastapi import APIRouter, Depends, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import encrypt_value, get_current_user, hash_password, require_role
from app.config import settings
from app.database import get_db
from app.models import ActivityLog, CertRequest, User
from app.services.packetfence import PacketFenceClient

router = APIRouter(prefix="/employee")
templates = Jinja2Templates(directory="app/templates")

CERTS_DIR = "certs"


def _ctx(request, user, **kwargs):
    return {
        "request": request,
        "user": user,
        "app_title": settings.app_title,
        "current_year": 2026,
        **kwargs,
    }


def _generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# --- Dashboard ---


@router.get("/dashboard", response_class=HTMLResponse)
@require_role("employee", "superadmin")
async def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result_pending = await db.execute(
        select(CertRequest)
        .where(CertRequest.status == "pendiente")
        .order_by(CertRequest.created_at.asc())
    )
    pending = result_pending.scalars().all()

    result_history = await db.execute(
        select(CertRequest)
        .where(CertRequest.status != "pendiente")
        .order_by(CertRequest.created_at.desc())
    )
    history = result_history.scalars().all()

    return templates.TemplateResponse(
        "employee/dashboard.html",
        _ctx(request, current_user, pending=pending, history=history),
    )


# --- Approve ---


@router.post("/approve/{req_id}")
@require_role("employee", "superadmin")
async def approve_request(
    request: Request,
    req_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CertRequest).where(CertRequest.id == req_id, CertRequest.status == "pendiente")
    )
    cert_req = result.scalar_one_or_none()
    if not cert_req:
        return RedirectResponse(url="/employee/dashboard", status_code=302)

    # Generate password and call PacketFence
    cert_password = _generate_password(16)
    cn = f"{cert_req.user.username}-{cert_req.id}"

    try:
        pf = PacketFenceClient()
        p12_bytes = await pf.create_cert(cn=cn, password=cert_password)
    except Exception as e:
        log = ActivityLog(
            user_id=current_user.id,
            action="cert_approve_error",
            detail=f"Error al crear certificado en PF para solicitud #{req_id}: {str(e)[:200]}",
            ip_address=request.client.host if request.client else "",
        )
        db.add(log)
        await db.commit()
        return RedirectResponse(url="/employee/dashboard", status_code=302)

    # Save .p12 file
    os.makedirs(CERTS_DIR, exist_ok=True)
    file_path = os.path.join(CERTS_DIR, f"{cn}.p12")
    with open(file_path, "wb") as f:
        f.write(p12_bytes)

    # Update request
    cert_req.status = "aprobada"
    cert_req.cert_file_path = file_path
    cert_req.cert_password_encrypted = encrypt_value(cert_password)
    cert_req.download_token = str(uuid.uuid4())
    cert_req.reviewed_by = current_user.id
    cert_req.reviewed_at = datetime.datetime.utcnow()

    log = ActivityLog(
        user_id=current_user.id,
        action="cert_approve",
        detail=f"Certificado aprobado para solicitud #{req_id} (alumno: {cert_req.user.username})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/dashboard", status_code=302)


# --- Reject ---


@router.post("/reject/{req_id}")
@require_role("employee", "superadmin")
async def reject_request(
    request: Request,
    req_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()
    reason = form.get("reason", "").strip() or "Sin motivo especificado"

    result = await db.execute(
        select(CertRequest).where(CertRequest.id == req_id, CertRequest.status == "pendiente")
    )
    cert_req = result.scalar_one_or_none()
    if not cert_req:
        return RedirectResponse(url="/employee/dashboard", status_code=302)

    cert_req.status = "rechazada"
    cert_req.reject_reason = reason
    cert_req.reviewed_by = current_user.id
    cert_req.reviewed_at = datetime.datetime.utcnow()

    log = ActivityLog(
        user_id=current_user.id,
        action="cert_reject",
        detail=f"Solicitud #{req_id} rechazada: {reason}",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/dashboard", status_code=302)


# --- Revoke ---


@router.post("/revoke/{req_id}")
@require_role("employee", "superadmin")
async def revoke_request(
    request: Request,
    req_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CertRequest).where(CertRequest.id == req_id, CertRequest.status == "aprobada")
    )
    cert_req = result.scalar_one_or_none()
    if not cert_req:
        return RedirectResponse(url="/employee/dashboard", status_code=302)

    # Call PacketFence to revoke
    cn = f"{cert_req.user.username}-{cert_req.id}"
    try:
        pf = PacketFenceClient()
        await pf.revoke_cert(cert_id=cn)
    except Exception:
        pass  # Log but continue — mark as revoked locally

    cert_req.status = "revocada"
    cert_req.revoked_at = datetime.datetime.utcnow()
    cert_req.download_token_used = True  # Prevent further downloads

    # Delete local .p12 file
    if cert_req.cert_file_path and os.path.exists(cert_req.cert_file_path):
        os.remove(cert_req.cert_file_path)

    log = ActivityLog(
        user_id=current_user.id,
        action="cert_revoke",
        detail=f"Certificado revocado para solicitud #{req_id} (alumno: {cert_req.user.username})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/dashboard", status_code=302)


# --- User Management ---


@router.get("/users", response_class=HTMLResponse)
@require_role("employee", "superadmin")
async def users_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return templates.TemplateResponse(
        "employee/users.html", _ctx(request, current_user, users=users)
    )


@router.post("/users/create")
@require_role("employee", "superadmin")
async def create_user(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    full_name = form.get("full_name", "").strip()
    role = form.get("role", "student")

    if not username or not password:
        return RedirectResponse(url="/employee/users", status_code=302)

    # Only superadmin can create superadmin
    if role == "superadmin" and current_user.role != "superadmin":
        role = "student"

    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        return RedirectResponse(url="/employee/users", status_code=302)

    user = User(
        username=username,
        password_hash=hash_password(password),
        full_name=full_name,
        role=role,
    )
    db.add(user)

    log = ActivityLog(
        user_id=current_user.id,
        action="user_create",
        detail=f"Usuario creado: {username} (rol: {role})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/users", status_code=302)


@router.post("/users/toggle/{user_id}")
@require_role("employee", "superadmin")
async def toggle_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or user.id == current_user.id:
        return RedirectResponse(url="/employee/users", status_code=302)

    user.is_active = not user.is_active

    log = ActivityLog(
        user_id=current_user.id,
        action="user_toggle",
        detail=f"Usuario {user.username} {'activado' if user.is_active else 'desactivado'}",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/users", status_code=302)


@router.post("/users/import-csv")
@require_role("employee", "superadmin")
async def import_csv(
    request: Request,
    csv_file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    content = await csv_file.read()
    text = content.decode("utf-8-sig").strip()
    lines = text.splitlines()

    imported_users = []
    for line in lines:
        username = line.strip().split(",")[0].strip()
        if not username:
            continue

        # Skip if already exists
        existing = await db.execute(select(User).where(User.username == username))
        if existing.scalar_one_or_none():
            continue

        password = _generate_password(12)
        user = User(
            username=username,
            password_hash=hash_password(password),
            full_name=username,
            role="student",
        )
        db.add(user)
        imported_users.append({"username": username, "password": password})

    if imported_users:
        log = ActivityLog(
            user_id=current_user.id,
            action="users_import",
            detail=f"Importados {len(imported_users)} alumnos desde CSV",
            ip_address=request.client.host if request.client else "",
        )
        db.add(log)
        await db.commit()

    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()

    return templates.TemplateResponse(
        "employee/users.html",
        _ctx(request, current_user, users=users, imported_users=imported_users),
    )
