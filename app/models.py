from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, default="")
    vlan = Column(Integer, nullable=False, default=0)
    pf_role_name = Column(String(100), nullable=True)
    pf_category_id = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)

    users = relationship("User", back_populates="group", lazy="selectin")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(200), nullable=False, default="")
    email = Column(String(200), nullable=False, default="")
    role = Column(String(20), nullable=False, default="student")  # student | employee | superadmin
    is_active = Column(Boolean, default=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)

    group = relationship("Group", back_populates="users", lazy="selectin")
    cert_requests = relationship("CertRequest", back_populates="user", lazy="selectin",
                                 foreign_keys="CertRequest.user_id")
    creator = relationship("User", remote_side="User.id", lazy="selectin")


class CertRequest(Base):
    __tablename__ = "cert_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(20), nullable=False, default="pendiente")  # pendiente | aprobada | rechazada | revocada
    hostname = Column(String(200), default="No disponible")
    user_agent = Column(Text, default="")
    ip_address = Column(String(45), default="")
    detected_os = Column(String(50), default="Desconocido")
    is_mobile = Column(Boolean, default=False)

    # Campos post-aprobacion
    cert_file_path = Column(String(500), nullable=True)
    cert_password_encrypted = Column(String(500), nullable=True)  # Fernet, cifrado reversible
    download_token = Column(String(100), unique=True, nullable=True, index=True)
    download_token_used = Column(Boolean, default=False)
    pf_cert_id = Column(String(200), nullable=True)

    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    reject_reason = Column(Text, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    downloaded_at = Column(DateTime, nullable=True)
    download_ip = Column(String(45), nullable=True)

    created_at = Column(DateTime, default=_utcnow)

    user = relationship("User", foreign_keys=[user_id], back_populates="cert_requests", lazy="selectin")
    reviewer = relationship("User", foreign_keys=[reviewed_by], lazy="selectin")


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    detail = Column(Text, default="")
    ip_address = Column(String(45), default="")
    created_at = Column(DateTime, default=_utcnow)

    user = relationship("User", lazy="selectin")


class AppSetting(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, default="")
