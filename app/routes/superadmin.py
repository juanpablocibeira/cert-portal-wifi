from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_role
from app.config import settings
from app.database import get_db
from app.models import ActivityLog, AppSetting, User
from app.services.packetfence import PacketFenceClient

router = APIRouter(prefix="/superadmin")
templates = Jinja2Templates(directory="app/templates")


def _ctx(request, user, **kwargs):
    return {
        "request": request,
        "user": user,
        "app_title": settings.app_title,
        "current_year": 2026,
        **kwargs,
    }


async def _get_setting(db, key: str, default: str = "") -> str:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    s = result.scalar_one_or_none()
    return s.value if s else default


async def _set_setting(db, key: str, value: str):
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    s = result.scalar_one_or_none()
    if s:
        s.value = value
    else:
        db.add(AppSetting(key=key, value=value))


@router.get("/settings", response_class=HTMLResponse)
@require_role("superadmin")
async def settings_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    pf_host = await _get_setting(db, "pf_host", settings.pf_host)
    pf_username = await _get_setting(db, "pf_username", settings.pf_username)
    pf_password = await _get_setting(db, "pf_password", settings.pf_password)
    pf_cert_profile = await _get_setting(db, "pf_cert_profile", settings.pf_cert_profile)

    return templates.TemplateResponse(
        "employee/settings.html",
        _ctx(
            request,
            current_user,
            pf_host=pf_host,
            pf_username=pf_username,
            pf_password=pf_password,
            pf_cert_profile=pf_cert_profile,
        ),
    )


@router.post("/settings")
@require_role("superadmin")
async def save_settings(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()
    await _set_setting(db, "pf_host", form.get("pf_host", "").strip())
    await _set_setting(db, "pf_username", form.get("pf_username", "").strip())

    # Only update password if provided
    pw = form.get("pf_password", "").strip()
    if pw:
        await _set_setting(db, "pf_password", pw)

    await _set_setting(db, "pf_cert_profile", form.get("pf_cert_profile", "").strip())

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
    pf_host = await _get_setting(db, "pf_host", settings.pf_host)
    pf_username = await _get_setting(db, "pf_username", settings.pf_username)
    pf_password = await _get_setting(db, "pf_password", settings.pf_password)
    pf_cert_profile = await _get_setting(db, "pf_cert_profile", settings.pf_cert_profile)

    pf = PacketFenceClient(
        host=pf_host,
        username=pf_username,
        password=pf_password,
        cert_profile=pf_cert_profile,
    )
    test_result = await pf.test_connection()

    return templates.TemplateResponse(
        "employee/settings.html",
        _ctx(
            request,
            current_user,
            pf_host=pf_host,
            pf_username=pf_username,
            pf_password=pf_password,
            pf_cert_profile=pf_cert_profile,
            test_result=test_result,
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
