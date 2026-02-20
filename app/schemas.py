from datetime import datetime
from typing import Optional

from pydantic import BaseModel


# --- Auth ---
class LoginForm(BaseModel):
    username: str
    password: str


# --- User ---
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str = ""
    role: str = "student"


class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# --- CertRequest ---
class CertRequestCreate(BaseModel):
    hostname: str = "No disponible"


class CertRequestOut(BaseModel):
    id: int
    user_id: int
    status: str
    hostname: str
    detected_os: str
    is_mobile: bool
    download_token: Optional[str] = None
    download_token_used: bool = False
    reviewed_by: Optional[int] = None
    reviewed_at: Optional[datetime] = None
    reject_reason: Optional[str] = None
    revoked_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class CertApproveRequest(BaseModel):
    pass


class CertRejectRequest(BaseModel):
    reason: str = ""


# --- Settings ---
class PFSettingsForm(BaseModel):
    pf_host: str
    pf_username: str
    pf_password: str
    pf_cert_profile: str


# --- Activity Log ---
class ActivityLogOut(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    detail: str
    ip_address: str
    created_at: datetime

    model_config = {"from_attributes": True}
