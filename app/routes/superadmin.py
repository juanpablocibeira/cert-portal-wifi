from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    decrypt_value,
    encrypt_value,
    get_current_user,
    require_role,
    validate_csrf,
)
from app.config import settings
from app.database import get_db
from app.models import ActivityLog, AppSetting, User
from app.services.packetfence import get_pf_client

router = APIRouter(prefix="/superadmin")
templates = Jinja2Templates(directory="app/templates")


def _ctx(request, user, **kwargs):
    return {
        "request": request,
        "user": user,
        "app_title": settings.app_title,
        "current_year": datetime.now(timezone.utc).year,
        "csrf_token": request.cookies.get("csrf_token", ""),
        **kwargs,
    }


async def _get_setting(db, key: str, default: str = "") -> str:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    s = result.scalar_one_or_none()
    if not s:
        return default
    # Decrypt pf_password
    if key == "pf_password" and s.value:
        try:
            return decrypt_value(s.value)
        except Exception:
            return s.value
    return s.value


async def _set_setting(db, key: str, value: str):
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    s = result.scalar_one_or_none()
    # Encrypt pf_password
    store_value = encrypt_value(value) if key == "pf_password" else value
    if s:
        s.value = store_value
    else:
        db.add(AppSetting(key=key, value=store_value))


@router.get("/settings", response_class=HTMLResponse)
@require_role("superadmin")
async def settings_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    pf_host = await _get_setting(db, "pf_host", settings.pf_host)
    pf_username = await _get_setting(db, "pf_username", settings.pf_username)
    pf_cert_profile = await _get_setting(db, "pf_cert_profile", settings.pf_cert_profile)
    pf_verify_ssl = (await _get_setting(db, "pf_verify_ssl", str(settings.pf_verify_ssl))).lower() in ("true", "1", "yes")

    # Password enmascarado — no enviamos el valor real al template
    raw_pw = await _get_setting(db, "pf_password", "")
    pf_password_set = bool(raw_pw)

    return templates.TemplateResponse(
        "employee/settings.html",
        _ctx(
            request,
            current_user,
            pf_host=pf_host,
            pf_username=pf_username,
            pf_password_set=pf_password_set,
            pf_cert_profile=pf_cert_profile,
            pf_verify_ssl=pf_verify_ssl,
        ),
    )


@router.post("/settings")
@require_role("superadmin")
async def save_settings(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    form = await request.form()
    await _set_setting(db, "pf_host", form.get("pf_host", "").strip())
    await _set_setting(db, "pf_username", form.get("pf_username", "").strip())

    # Only update password if provided
    pw = form.get("pf_password", "").strip()
    if pw:
        await _set_setting(db, "pf_password", pw)

    await _set_setting(db, "pf_cert_profile", form.get("pf_cert_profile", "").strip())
    await _set_setting(db, "pf_verify_ssl", "true" if form.get("pf_verify_ssl") else "false")

    log = ActivityLog(
        user_id=current_user.id,
        action="settings_update",
        detail="Configuracion de PacketFence actualizada",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/superadmin/settings", status_code=302)


@router.post("/test-connection")
@require_role("superadmin")
async def test_connection(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    pf = await get_pf_client(db)
    diagnostic_steps = await pf.test_connection_detailed()

    # Re-read settings for template
    pf_host = await _get_setting(db, "pf_host", settings.pf_host)
    pf_username = await _get_setting(db, "pf_username", settings.pf_username)
    pf_cert_profile = await _get_setting(db, "pf_cert_profile", settings.pf_cert_profile)
    pf_verify_ssl = (await _get_setting(db, "pf_verify_ssl", str(settings.pf_verify_ssl))).lower() in ("true", "1", "yes")
    raw_pw = await _get_setting(db, "pf_password", "")
    pf_password_set = bool(raw_pw)

    return templates.TemplateResponse(
        "employee/settings.html",
        _ctx(
            request,
            current_user,
            pf_host=pf_host,
            pf_username=pf_username,
            pf_password_set=pf_password_set,
            pf_cert_profile=pf_cert_profile,
            pf_verify_ssl=pf_verify_ssl,
            diagnostic_steps=diagnostic_steps,
        ),
    )


@router.post("/list-profiles")
@require_role("superadmin")
async def list_profiles(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    pf = await get_pf_client(db)
    profiles = []
    profiles_error = ""
    try:
        profiles = await pf.list_profiles()
        print(f"[PF-PROFILES] Perfiles encontrados: {profiles}")
    except Exception as e:
        profiles_error = str(e)[:300]
        print(f"[PF-PROFILES] Error: {profiles_error}")

    # Re-read settings for template
    pf_host = await _get_setting(db, "pf_host", settings.pf_host)
    pf_username = await _get_setting(db, "pf_username", settings.pf_username)
    pf_cert_profile = await _get_setting(db, "pf_cert_profile", settings.pf_cert_profile)
    pf_verify_ssl = (await _get_setting(db, "pf_verify_ssl", str(settings.pf_verify_ssl))).lower() in ("true", "1", "yes")
    raw_pw = await _get_setting(db, "pf_password", "")
    pf_password_set = bool(raw_pw)

    return templates.TemplateResponse(
        "employee/settings.html",
        _ctx(
            request,
            current_user,
            pf_host=pf_host,
            pf_username=pf_username,
            pf_password_set=pf_password_set,
            pf_cert_profile=pf_cert_profile,
            pf_verify_ssl=pf_verify_ssl,
            pki_profiles=profiles,
            profiles_error=profiles_error,
        ),
    )


@router.get("/logs", response_class=HTMLResponse)
@require_role("superadmin")
async def logs_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    page = int(request.query_params.get("page", 1))
    per_page = 50

    # Count total
    count_result = await db.execute(select(func.count(ActivityLog.id)))
    total = count_result.scalar()
    total_pages = max(1, (total + per_page - 1) // per_page)

    result = await db.execute(
        select(ActivityLog)
        .order_by(ActivityLog.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    logs = result.scalars().all()

    return templates.TemplateResponse(
        "employee/logs.html",
        _ctx(request, current_user, logs=logs, page=page, total_pages=total_pages),
    )
