import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select, text

from app.auth import (
    AuthRedirectException,
    ForbiddenException,
    encrypt_value,
    generate_csrf_token,
    hash_password,
)
from app.config import settings
from app.database import async_session, engine, init_db
from app.models import AppSetting, User
from app.routes import auth as auth_routes
from app.routes import employee as employee_routes
from app.routes import student as student_routes
from app.routes import superadmin as superadmin_routes

logger = logging.getLogger("cert-portal")


# --- Schema migration for SQLite ---

async def _migrate_schema():
    """Add missing columns to existing SQLite tables."""
    migrations = [
        ("users", "email", "TEXT NOT NULL DEFAULT ''"),
        ("users", "created_by", "INTEGER"),
        ("users", "group_id", "INTEGER"),
        ("cert_requests", "pf_cert_id", "TEXT"),
        ("cert_requests", "downloaded_at", "DATETIME"),
        ("cert_requests", "download_ip", "TEXT"),
    ]
    async with engine.begin() as conn:
        for table, column, col_type in migrations:
            try:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                logger.info(f"Migracion: columna '{column}' agregada a '{table}'")
            except Exception:
                pass  # Column already exists


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Crear tablas
    await init_db()

    # Migraciones de schema
    await _migrate_schema()

    # Crear superadmin si no existe y guardar config PF inicial
    async with async_session() as db:
        result = await db.execute(
            select(User).where(User.username == settings.superadmin_username)
        )
        if not result.scalar_one_or_none():
            superadmin = User(
                username=settings.superadmin_username,
                password_hash=hash_password(settings.superadmin_password),
                full_name="Administrador",
                email=settings.superadmin_email,
                role="superadmin",
                is_active=True,
            )
            db.add(superadmin)
            await db.commit()

        # Guardar config PF en AppSettings si no existen
        pf_defaults = {
            "pf_host": settings.pf_host,
            "pf_username": settings.pf_username,
            "pf_cert_profile": settings.pf_cert_profile,
            "pf_verify_ssl": str(settings.pf_verify_ssl),
        }
        for key, default_val in pf_defaults.items():
            existing = await db.execute(select(AppSetting).where(AppSetting.key == key))
            if not existing.scalar_one_or_none():
                db.add(AppSetting(key=key, value=default_val))

        # Guardar pf_password cifrado si no existe
        existing_pw = await db.execute(select(AppSetting).where(AppSetting.key == "pf_password"))
        if not existing_pw.scalar_one_or_none() and settings.pf_password:
            db.add(AppSetting(key="pf_password", value=encrypt_value(settings.pf_password)))

        await db.commit()

    logger.info("Sistema inicializado")
    yield


app = FastAPI(title=settings.app_title, lifespan=lifespan)

# Rate limiting
app.state.limiter = auth_routes.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# --- Exception handlers ---

@app.exception_handler(AuthRedirectException)
async def auth_redirect_handler(request: Request, exc: AuthRedirectException):
    return RedirectResponse(url=exc.redirect_url, status_code=302)


@app.exception_handler(ForbiddenException)
async def forbidden_handler(request: Request, exc: ForbiddenException):
    return HTMLResponse(
        content=f"""
        <html><body style="font-family:sans-serif;text-align:center;padding:80px">
        <h1>403 — Acceso denegado</h1>
        <p>{exc.detail}</p>
        <a href="/login">Volver al inicio</a>
        </body></html>
        """,
        status_code=403,
    )


# --- Middleware: security headers + CSRF cookie ---

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Set CSRF cookie if not present
    if "csrf_token" not in request.cookies:
        csrf_token = generate_csrf_token()
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,  # JS needs to read it for forms
            samesite="lax",
            max_age=settings.jwt_expire_minutes * 60,
        )

    return response


# Root redirect
@app.get("/")
async def root():
    return RedirectResponse(url="/login", status_code=302)


# Include routers
app.include_router(auth_routes.router)
app.include_router(student_routes.router)
app.include_router(employee_routes.router)
app.include_router(superadmin_routes.router)
