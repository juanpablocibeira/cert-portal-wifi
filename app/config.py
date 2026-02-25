from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_title: str = "Portal de Certificados WiFi"
    secret_key: str = "cambiar-por-clave-segura"
    fernet_key: str = ""

    database_url: str = "sqlite+aiosqlite:///./data/portal.db"

    superadmin_username: str = "admin"
    superadmin_password: str = "admin"
    superadmin_email: str = ""

    pf_host: str = "https://localhost:9999"
    pf_username: str = "admin"
    pf_password: str = ""
    pf_cert_profile: str = "default"
    pf_verify_ssl: bool = False

    jwt_expire_minutes: int = 480
    node_sync_interval: int = 30  # seconds between node sync checks

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
