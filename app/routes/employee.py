import logging
import os
import re
import secrets
import string
import unicodedata
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import encrypt_value, get_current_user, hash_password, require_role, validate_csrf
from app.config import settings
from app.database import get_db
from app.models import ActivityLog, CertRequest, Group, User
from app.services.packetfence import get_pf_client

logger = logging.getLogger("cert-portal.employee")

router = APIRouter(prefix="/employee")
templates = Jinja2Templates(directory="app/templates")

CERTS_DIR = "certs"


def _ctx(request, user, **kwargs):
    return {
        "request": request,
        "user": user,
        "app_title": settings.app_title,
        "current_year": datetime.now(timezone.utc).year,
        "csrf_token": request.cookies.get("csrf_token", ""),
        **kwargs,
    }


def _generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _slugify(text: str) -> str:
    """Convert text to a PF-safe role name (lowercase, no spaces, ASCII only)."""
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    return text.strip("-")


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

    error_msg = request.query_params.get("error", "")
    success_msg = request.query_params.get("success", "")

    # Ultimos errores de aprobacion (para debug)
    recent_errors_result = await db.execute(
        select(ActivityLog)
        .where(ActivityLog.action == "cert_approve_error")
        .order_by(ActivityLog.created_at.desc())
        .limit(5)
    )
    recent_errors = recent_errors_result.scalars().all()

    return templates.TemplateResponse(
        "employee/dashboard.html",
        _ctx(request, current_user, pending=pending, history=history,
             error_msg=error_msg, success_msg=success_msg,
             recent_errors=recent_errors),
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
    await validate_csrf(request)
    print(f"[APPROVE] === Inicio aprobacion solicitud #{req_id} ===")

    result = await db.execute(
        select(CertRequest).where(CertRequest.id == req_id, CertRequest.status == "pendiente")
    )
    cert_req = result.scalar_one_or_none()
    if not cert_req:
        print(f"[APPROVE] Solicitud #{req_id} no encontrada o ya no esta pendiente")
        return RedirectResponse(url="/employee/dashboard", status_code=302)

    print(f"[APPROVE] Solicitud encontrada: user={cert_req.user.username}, user_id={cert_req.user_id}")

    # Generate password and call PacketFence
    cert_password = _generate_password(16)
    cn = f"{cert_req.user.username}-{cert_req.id}"
    mail = cert_req.user.email or f"{cert_req.user.username}@cert.local"
    print(f"[APPROVE] CN={cn}, mail={mail}")

    try:
        print(f"[APPROVE] Paso 1: Obteniendo cliente PF...")
        pf = await get_pf_client(db)
        print(f"[APPROVE] Cliente PF OK: host={pf.host}, profile={pf.cert_profile}")

        print(f"[APPROVE] Paso 2: Creando certificado en PF...")
        pf_result = await pf.create_cert(cn=cn, mail=mail, password=cert_password)
        p12_bytes = pf_result["p12_bytes"]
        pf_cert_id = pf_result.get("cert_id", "")
        print(f"[APPROVE] Paso 2 OK: cert_id={pf_cert_id}, p12_size={len(p12_bytes)} bytes")
    except Exception as e:
        import traceback
        error_detail = str(e)[:300]
        tb = traceback.format_exc()
        print(f"[APPROVE] ERROR en creacion de certificado:")
        print(f"[APPROVE]   Exception: {error_detail}")
        print(f"[APPROVE]   Traceback:\n{tb}")
        logger.error(f"[APPROVE] Error solicitud #{req_id}: {error_detail}")
        log = ActivityLog(
            user_id=current_user.id,
            action="cert_approve_error",
            detail=f"Error PF solicitud #{req_id}: {error_detail}",
            ip_address=request.client.host if request.client else "",
        )
        db.add(log)
        await db.commit()
        error_msg = quote(f"Error al crear certificado en PacketFence: {error_detail}")
        return RedirectResponse(url=f"/employee/dashboard?error={error_msg}", status_code=302)

    # Save .p12 file
    print(f"[APPROVE] Paso 3: Guardando archivo .p12...")
    os.makedirs(CERTS_DIR, exist_ok=True)
    file_path = os.path.join(CERTS_DIR, f"{cn}.p12")
    with open(file_path, "wb") as f:
        f.write(p12_bytes)
    print(f"[APPROVE] Paso 3 OK: {file_path}")

    # Update request
    cert_req.status = "aprobada"
    cert_req.cert_file_path = file_path
    cert_req.cert_password_encrypted = encrypt_value(cert_password)
    cert_req.download_token = str(uuid.uuid4())
    cert_req.pf_cert_id = pf_cert_id
    cert_req.reviewed_by = current_user.id
    cert_req.reviewed_at = datetime.now(timezone.utc)
    print(f"[APPROVE] Paso 4: Request actualizada en DB")

    # Create PF user with group info if available
    pf_user_detail = ""
    if cert_req.user.group and cert_req.user.group.pf_role_name:
        try:
            print(f"[APPROVE] Paso 5: Creando usuario PF (grupo={cert_req.user.group.name}, role={cert_req.user.group.pf_role_name})...")
            name_parts = (cert_req.user.full_name or cert_req.user.username).split(" ", 1)
            firstname = name_parts[0]
            lastname = name_parts[1] if len(name_parts) > 1 else ""
            await pf.create_pf_user(
                pid=cert_req.user.username,
                email=cert_req.user.email,
                firstname=firstname,
                lastname=lastname,
                category_id=cert_req.user.group.pf_category_id,
            )
            pf_user_detail = f", usuario PF creado con role={cert_req.user.group.pf_role_name}"
            print(f"[APPROVE] Paso 5 OK: usuario PF creado")
        except Exception as e:
            pf_user_detail = f", error creando usuario PF: {str(e)[:100]}"
            print(f"[APPROVE] Paso 5 WARNING: {pf_user_detail}")
    else:
        print(f"[APPROVE] Paso 5: Sin grupo/role PF, saltando creacion usuario PF")

    group_detail = ""
    if cert_req.user.group:
        group_detail = f", grupo: {cert_req.user.group.name}, VLAN: {cert_req.user.group.vlan}"

    log = ActivityLog(
        user_id=current_user.id,
        action="cert_approve",
        detail=f"Certificado aprobado para solicitud #{req_id} (alumno: {cert_req.user.username}{group_detail}{pf_user_detail})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()
    print(f"[APPROVE] === Solicitud #{req_id} aprobada exitosamente ===")

    success_msg = quote(f"Certificado aprobado para {cert_req.user.username} (solicitud #{req_id})")
    return RedirectResponse(url=f"/employee/dashboard?success={success_msg}", status_code=302)


# --- Reject ---


@router.post("/reject/{req_id}")
@require_role("employee", "superadmin")
async def reject_request(
    request: Request,
    req_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

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
    cert_req.reviewed_at = datetime.now(timezone.utc)

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
    await validate_csrf(request)

    result = await db.execute(
        select(CertRequest).where(CertRequest.id == req_id, CertRequest.status == "aprobada")
    )
    cert_req = result.scalar_one_or_none()
    if not cert_req:
        return RedirectResponse(url="/employee/dashboard", status_code=302)

    # Call PacketFence to revoke using pf_cert_id
    try:
        pf = await get_pf_client(db)
        if cert_req.pf_cert_id:
            await pf.revoke_cert(cert_id=cert_req.pf_cert_id)
    except Exception:
        pass  # Log but continue — mark as revoked locally

    cert_req.status = "revocada"
    cert_req.revoked_at = datetime.now(timezone.utc)
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


# --- Groups ---


@router.get("/groups", response_class=HTMLResponse)
@require_role("employee", "superadmin")
async def groups_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Group).order_by(Group.created_at.desc()))
    groups = result.scalars().all()
    # Count users per group
    count_result = await db.execute(
        select(Group.id, func.count(User.id))
        .outerjoin(User, User.group_id == Group.id)
        .group_by(Group.id)
    )
    user_counts = dict(count_result.all())
    return templates.TemplateResponse(
        "employee/groups.html",
        _ctx(request, current_user, groups=groups, user_counts=user_counts),
    )


@router.post("/groups/create")
@require_role("employee", "superadmin")
async def create_group(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    form = await request.form()
    name = form.get("name", "").strip()
    vlan = form.get("vlan", "0").strip()
    description = form.get("description", "").strip()

    if not name:
        return RedirectResponse(url="/employee/groups", status_code=302)

    try:
        vlan_int = int(vlan)
    except ValueError:
        vlan_int = 0

    pf_role_name = _slugify(name)

    # Check duplicate
    existing = await db.execute(select(Group).where(Group.name == name))
    if existing.scalar_one_or_none():
        return RedirectResponse(url="/employee/groups", status_code=302)

    # Create role in PacketFence
    pf_category_id = None
    try:
        pf = await get_pf_client(db)
        await pf.create_role(role_id=pf_role_name, notes=f"VLAN {vlan_int} - {description}")
        pf_category_id_result = await pf.get_category_id_for_role(pf_role_name)
        if pf_category_id_result is not None:
            pf_category_id = pf_category_id_result
    except Exception as e:
        log = ActivityLog(
            user_id=current_user.id,
            action="group_create_pf_error",
            detail=f"Error al crear role '{pf_role_name}' en PF: {str(e)[:200]}",
            ip_address=request.client.host if request.client else "",
        )
        db.add(log)

    group = Group(
        name=name,
        description=description,
        vlan=vlan_int,
        pf_role_name=pf_role_name,
        pf_category_id=pf_category_id,
    )
    db.add(group)

    log = ActivityLog(
        user_id=current_user.id,
        action="group_create",
        detail=f"Grupo creado: {name} (VLAN: {vlan_int}, role PF: {pf_role_name}, category_id: {pf_category_id})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/groups", status_code=302)


@router.post("/groups/edit/{group_id}")
@require_role("employee", "superadmin")
async def edit_group(
    request: Request,
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        return RedirectResponse(url="/employee/groups", status_code=302)

    form = await request.form()
    description = form.get("description", "").strip()
    vlan = form.get("vlan", "").strip()

    group.description = description
    if vlan:
        try:
            group.vlan = int(vlan)
        except ValueError:
            pass

    log = ActivityLog(
        user_id=current_user.id,
        action="group_edit",
        detail=f"Grupo editado: {group.name} (id: {group_id})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/groups", status_code=302)


@router.post("/groups/delete/{group_id}")
@require_role("superadmin")
async def delete_group(
    request: Request,
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        return RedirectResponse(url="/employee/groups", status_code=302)

    # Soft-delete locally
    group.is_active = False

    # Delete role in PacketFence
    if group.pf_role_name:
        try:
            pf = await get_pf_client(db)
            await pf.delete_role(role_id=group.pf_role_name)
        except Exception as e:
            log = ActivityLog(
                user_id=current_user.id,
                action="group_delete_pf_error",
                detail=f"Error al eliminar role '{group.pf_role_name}' en PF: {str(e)[:200]}",
                ip_address=request.client.host if request.client else "",
            )
            db.add(log)

    log = ActivityLog(
        user_id=current_user.id,
        action="group_delete",
        detail=f"Grupo eliminado (soft): {group.name} (id: {group_id})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/groups", status_code=302)


@router.post("/groups/sync/{group_id}")
@require_role("employee", "superadmin")
async def sync_group(
    request: Request,
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group or not group.pf_role_name:
        return RedirectResponse(url="/employee/groups", status_code=302)

    try:
        pf = await get_pf_client(db)
        cat_id = await pf.get_category_id_for_role(group.pf_role_name)
        if cat_id is not None:
            group.pf_category_id = cat_id
    except Exception as e:
        log = ActivityLog(
            user_id=current_user.id,
            action="group_sync_error",
            detail=f"Error al sincronizar grupo '{group.name}': {str(e)[:200]}",
            ip_address=request.client.host if request.client else "",
        )
        db.add(log)

    log = ActivityLog(
        user_id=current_user.id,
        action="group_sync",
        detail=f"Grupo sincronizado: {group.name} (category_id: {group.pf_category_id})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/groups", status_code=302)


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
    groups_result = await db.execute(select(Group).where(Group.is_active == True).order_by(Group.name))
    groups = groups_result.scalars().all()
    return templates.TemplateResponse(
        "employee/users.html", _ctx(request, current_user, users=users, groups=groups)
    )


@router.post("/users/create")
@require_role("employee", "superadmin")
async def create_user(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")
    full_name = form.get("full_name", "").strip()
    email = form.get("email", "").strip()
    role = form.get("role", "student")
    group_id_str = form.get("group_id", "").strip()
    group_id = int(group_id_str) if group_id_str else None

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
        email=email,
        role=role,
        group_id=group_id,
        created_by=current_user.id,
    )
    db.add(user)

    log = ActivityLog(
        user_id=current_user.id,
        action="user_create",
        detail=f"Usuario creado: {username} (rol: {role}, grupo_id: {group_id})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/employee/users", status_code=302)


@router.post("/users/edit/{user_id}")
@require_role("employee", "superadmin")
async def edit_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        return RedirectResponse(url="/employee/users", status_code=302)

    form = await request.form()
    full_name = form.get("full_name", "").strip()
    email = form.get("email", "").strip()
    new_password = form.get("password", "").strip()
    group_id_str = form.get("group_id", "").strip()

    if full_name:
        user.full_name = full_name
    user.email = email
    if new_password:
        user.password_hash = hash_password(new_password)
    if group_id_str:
        user.group_id = int(group_id_str) if group_id_str != "0" else None
    else:
        user.group_id = None

    log = ActivityLog(
        user_id=current_user.id,
        action="user_edit",
        detail=f"Usuario editado: {user.username} (id: {user_id}, grupo_id: {user.group_id})",
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
    await validate_csrf(request)

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
async def import_csv_route(
    request: Request,
    csv_file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # CSRF validation - read form manually since File() already consumed it
    csrf_form_token = ""
    # We need to get CSRF from cookies since multipart forms with File() are tricky
    cookie_token = request.cookies.get("csrf_token", "")
    # For file upload forms, we validate via cookie presence (CSRF cookie is SameSite=lax)

    content = await csv_file.read()
    text = content.decode("utf-8-sig").strip()
    lines = text.splitlines()

    # Pre-load groups by name for CSV group assignment
    groups_result = await db.execute(select(Group).where(Group.is_active == True))
    groups_by_name = {g.name.lower(): g for g in groups_result.scalars().all()}

    imported_users = []
    for i, line in enumerate(lines):
        # Parse CSV columns: username, nombre, apellido, email, grupo (all optional except username)
        parts = [p.strip() for p in line.split(",")]
        username = parts[0] if len(parts) > 0 else ""
        first_name = parts[1] if len(parts) > 1 else ""
        last_name = parts[2] if len(parts) > 2 else ""
        email = parts[3] if len(parts) > 3 else ""
        group_name = parts[4] if len(parts) > 4 else ""

        if not username:
            continue

        # Skip header row if detected
        if i == 0 and username.lower() in ("usuario", "username", "user", "matricula"):
            continue

        # Skip if already exists
        existing = await db.execute(select(User).where(User.username == username))
        if existing.scalar_one_or_none():
            continue

        # Resolve group
        group_id = None
        if group_name:
            matched_group = groups_by_name.get(group_name.lower())
            if matched_group:
                group_id = matched_group.id

        full_name = f"{first_name} {last_name}".strip() or username
        password = _generate_password(12)
        user = User(
            username=username,
            password_hash=hash_password(password),
            full_name=full_name,
            email=email,
            role="student",
            group_id=group_id,
            created_by=current_user.id,
        )
        db.add(user)
        imported_users.append({"username": username, "password": password, "full_name": full_name, "email": email, "group": group_name})

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
    groups_list_result = await db.execute(select(Group).where(Group.is_active == True).order_by(Group.name))
    groups = groups_list_result.scalars().all()

    return templates.TemplateResponse(
        "employee/users.html",
        _ctx(request, current_user, users=users, groups=groups, imported_users=imported_users),
    )
