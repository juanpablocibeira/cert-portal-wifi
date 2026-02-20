from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select

from app.auth import hash_password
from app.config import settings
from app.database import async_session, init_db
from app.models import User
from app.routes import auth as auth_routes
from app.routes import employee as employee_routes
from app.routes import student as student_routes
from app.routes import superadmin as superadmin_routes


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Crear tablas
    await init_db()

    # Crear superadmin si no existe
    async with async_session() as db:
        result = await db.execute(
            select(User).where(User.username == settings.superadmin_username)
        )
        if not result.scalar_one_or_none():
            superadmin = User(
                username=settings.superadmin_username,
                password_hash=hash_password(settings.superadmin_password),
                full_name="Administrador",
                role="superadmin",
                is_active=True,
            )
            db.add(superadmin)
            await db.commit()

    yield


app = FastAPI(title=settings.app_title, lifespan=lifespan)

# Rate limiting
app.state.limiter = auth_routes.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
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
