from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import create_access_token, get_current_user, verify_password
from app.config import settings
from app.database import get_db
from app.models import ActivityLog, User

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
limiter = Limiter(key_func=get_remote_address)


def _ctx(request: Request, **kwargs):
    return {"request": request, "app_title": settings.app_title, "current_year": 2026, **kwargs}


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, current_user: User = Depends(get_current_user)):
    if current_user:
        return _redirect_by_role(current_user)
    return templates.TemplateResponse("login.html", _ctx(request))


@router.post("/login", response_class=HTMLResponse)
@limiter.limit("5/5minutes")
async def login_post(request: Request, db: AsyncSession = Depends(get_db)):
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html", _ctx(request, error="Usuario o contrasena incorrectos."), status_code=401
        )

    if not user.is_active:
        return templates.TemplateResponse(
            "login.html", _ctx(request, error="Tu cuenta esta desactivada. Contacta al administrador."), status_code=403
        )

    # Log activity
    log = ActivityLog(
        user_id=user.id,
        action="login",
        detail=f"Inicio de sesion exitoso",
        ip_address=request.client.host if request.client else "",
    )
    db.add(log)
    await db.commit()

    token = create_access_token({"sub": user.username})
    response = _redirect_by_role(user)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.jwt_expire_minutes * 60,
    )
    return response


@router.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


def _redirect_by_role(user: User) -> RedirectResponse:
    if user.role == "student":
        return RedirectResponse(url="/student/dashboard", status_code=302)
    return RedirectResponse(url="/employee/dashboard", status_code=302)
