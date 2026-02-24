from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import decrypt_value, get_current_user, require_role, validate_csrf
from app.config import settings
from app.database import get_db
from app.models import ActivityLog, CertRequest, User
from app.services.device_detection import detect_os, is_mobile

router = APIRouter(prefix="/student")
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


@router.get("/dashboard", response_class=HTMLResponse)
@require_role("student")
async def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    ua = request.headers.get("user-agent", "")
    result = await db.execute(
        select(CertRequest)
        .where(CertRequest.user_id == current_user.id)
        .order_by(CertRequest.created_at.desc())
    )
    requests = result.scalars().all()

    return templates.TemplateResponse(
        "student/dashboard.html",
        _ctx(
            request,
            current_user,
            requests=requests,
            is_mobile=is_mobile(ua),
            detected_os=detect_os(ua),
        ),
    )


@router.post("/request")
@require_role("student")
async def create_request(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await validate_csrf(request)

    ua = request.headers.get("user-agent", "")

    if is_mobile(ua):
        return RedirectResponse(url="/student/dashboard?error=movil", status_code=302)

    form = await request.form()
    hostname = form.get("hostname", "").strip() or "No disponible"

    cert_req = CertRequest(
        user_id=current_user.id,
        status="pendiente",
        hostname=hostname,
        user_agent=ua,
        ip_address=request.client.host if request.client else "",
        detected_os=detect_os(ua),
        is_mobile=False,
    )
    db.add(cert_req)

    log = ActivityLog(
        user_id=current_user.id,
        action="cert_request",
        detail=f"Solicitud de certificado creada (equipo: {hostname})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    return RedirectResponse(url="/student/dashboard", status_code=302)


@router.get("/download/{token}", response_class=HTMLResponse)
@require_role("student")
async def download_page(
    request: Request,
    token: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CertRequest).where(
            CertRequest.download_token == token,
            CertRequest.user_id == current_user.id,
            CertRequest.status == "aprobada",
        )
    )
    cert_req = result.scalar_one_or_none()

    if not cert_req:
        return templates.TemplateResponse(
            "student/dashboard.html",
            _ctx(request, current_user, requests=[], is_mobile=False, detected_os="", message="Enlace no valido.", message_type="error"),
        )

    if cert_req.download_token_used:
        return templates.TemplateResponse(
            "student/dashboard.html",
            _ctx(request, current_user, requests=[], is_mobile=False, detected_os="", message="Este certificado ya fue descargado.", message_type="error"),
        )

    cert_password = decrypt_value(cert_req.cert_password_encrypted)

    return templates.TemplateResponse(
        "student/download.html",
        _ctx(
            request,
            current_user,
            cert_password=cert_password,
            token=token,
            detected_os=cert_req.detected_os,
        ),
    )


@router.get("/download/{token}/file")
@require_role("student")
async def download_file(
    request: Request,
    token: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CertRequest).where(
            CertRequest.download_token == token,
            CertRequest.user_id == current_user.id,
            CertRequest.status == "aprobada",
        )
    )
    cert_req = result.scalar_one_or_none()

    if not cert_req or cert_req.download_token_used:
        return RedirectResponse(url="/student/dashboard", status_code=302)

    # Mark as used and record download info
    cert_req.download_token_used = True
    cert_req.downloaded_at = datetime.now(timezone.utc)
    cert_req.download_ip = request.client.host if request.client else ""

    log = ActivityLog(
        user_id=current_user.id,
        action="cert_download",
        detail=f"Certificado descargado (solicitud #{cert_req.id})",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    filename = f"certificado_{current_user.username}.p12"
    return FileResponse(
        path=cert_req.cert_file_path,
        filename=filename,
        media_type="application/x-pkcs12",
    )
