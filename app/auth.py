import functools
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.fernet import Fernet
from fastapi import Depends, Request
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"


# --- Custom exceptions for auth flow ---

class AuthRedirectException(Exception):
    """Raised when user is not authenticated and should be redirected to login."""
    def __init__(self, redirect_url: str = "/login"):
        self.redirect_url = redirect_url


class ForbiddenException(Exception):
    """Raised when user does not have the required role."""
    def __init__(self, detail: str = "No tienes permisos para acceder a esta seccion."):
        self.detail = detail


# --- Password helpers ---

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# --- JWT ---

def create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.jwt_expire_minutes
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


async def get_current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            return None
    except JWTError:
        return None
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user and not user.is_active:
        return None
    return user


# --- Role-based access control ---

def require_role(*roles: str):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get("request") or (args[0] if args else None)
            user = kwargs.get("current_user")
            if not user:
                raise AuthRedirectException("/login")
            if user.role not in roles:
                raise ForbiddenException()
            return await func(*args, **kwargs)

        return wrapper

    return decorator


# --- CSRF ---

def generate_csrf_token() -> str:
    return secrets.token_hex(32)


async def validate_csrf(request: Request):
    """Validate CSRF token from form data against cookie.

    Raises ForbiddenException if tokens don't match.
    """
    form = await request.form()
    form_token = form.get("csrf_token", "")
    cookie_token = request.cookies.get("csrf_token", "")
    if not form_token or not cookie_token or form_token != cookie_token:
        raise ForbiddenException("Token CSRF invalido. Recarga la pagina e intenta de nuevo.")


# --- Fernet encryption ---

def _get_fernet() -> Fernet:
    return Fernet(settings.fernet_key.encode())


def encrypt_value(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt_value(encrypted: str) -> str:
    return _get_fernet().decrypt(encrypted.encode()).decode()
