import logging
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings

logger = logging.getLogger("cert-portal.pf")


class PacketFenceClient:
    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cert_profile: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        self.host = (host or settings.pf_host).rstrip("/")
        self.username = username or settings.pf_username
        self.password = password or settings.pf_password
        self.cert_profile = cert_profile or settings.pf_cert_profile
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0)

    async def _ensure_token(self, force: bool = False):
        if self._token and not force:
            return
        async with self._client() as client:
            resp = await client.post(
                f"{self.host}/api/v1/login",
                json={"username": self.username, "password": self.password},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("token") or data.get("access_token")

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        await self._ensure_token()
        async with self._client() as client:
            resp = await client.request(
                method, f"{self.host}{path}", headers=self._auth_headers(), **kwargs
            )
            # Retry on 401
            if resp.status_code == 401:
                await self._ensure_token(force=True)
                resp = await client.request(
                    method, f"{self.host}{path}", headers=self._auth_headers(), **kwargs
                )
            return resp

    async def test_connection(self) -> dict:
        """Test connection to PacketFence. Returns {"ok": bool, "detail": str}."""
        try:
            await self._ensure_token(force=True)
            return {"ok": True, "detail": "Conexion exitosa con PacketFence."}
        except httpx.HTTPStatusError as e:
            return {"ok": False, "detail": f"Error HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except Exception as e:
            return {"ok": False, "detail": f"Error de conexion: {str(e)[:200]}"}

    async def create_cert(self, cn: str, mail: str, password: str, profile_id: Optional[str] = None) -> dict:
        """Create a certificate in PacketFence.

        Two-step process:
          1. POST /api/v1/pki/certs  -> creates cert, returns JSON with ID
          2. GET  /api/v1/pki/cert/{ID}/download/p12  -> downloads the .p12 binary

        Returns dict with "p12_bytes" and "cert_id".
        """
        # Step 1: create the cert (profile_id must be a string)
        resp = await self._request(
            "POST",
            "/api/v1/pki/certs",
            json={
                "cn": cn,
                "mail": mail,
                "profile_id": str(profile_id or self.cert_profile),
                "p12_password": password,
            },
        )
        # PF returns 422 on success (quirk), but also includes the cert data
        data = resp.json()
        items = data.get("items", [])
        if not items:
            raise ValueError(f"PacketFence no devolvio certificado. Status: {data.get('status')}, Error: {data.get('error', '')}")

        cert_id = str(items[0].get("ID", ""))
        if not cert_id:
            raise ValueError(f"PacketFence no devolvio ID de certificado. Keys: {list(items[0].keys())}")

        logger.info(f"Certificado creado en PF: ID={cert_id}, CN={cn}")

        # Step 2: download the .p12 binary
        p12_resp = await self._request("GET", f"/api/v1/pki/cert/{cert_id}/download/p12")
        if p12_resp.status_code != 200 or len(p12_resp.content) == 0:
            raise ValueError(f"No se pudo descargar el .p12 para cert ID {cert_id}. HTTP {p12_resp.status_code}, Size: {len(p12_resp.content)}")

        return {"p12_bytes": p12_resp.content, "cert_id": cert_id}

    async def revoke_cert(self, cert_id: str, reason: int = 2) -> dict:
        """Revoke a certificate by its PF cert ID.

        Uses DELETE /api/v1/pki/cert/{id} with reason (int).
        Note: revocation via API may not work on all PF versions.
        The portal marks the cert as revoked locally regardless.
        """
        try:
            resp = await self._request(
                "DELETE",
                f"/api/v1/pki/cert/{cert_id}",
                json={"reason": reason},
            )
            logger.info(f"Revocacion enviada a PF para cert ID {cert_id}: HTTP {resp.status_code}")
            if resp.content:
                return resp.json()
            return {"ok": True, "detail": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning(f"Error al revocar cert {cert_id} en PF: {e}")
            return {"ok": False, "detail": str(e)[:200]}

    async def create_role(self, role_id: str, notes: str = "") -> dict:
        """Create a role in PacketFence. POST /api/v1/config/roles"""
        resp = await self._request(
            "POST",
            "/api/v1/config/roles",
            json={"id": role_id, "notes": notes},
        )
        logger.info(f"Role creado en PF: {role_id}, HTTP {resp.status_code}")
        if resp.content:
            return resp.json()
        return {"ok": True, "status": resp.status_code}

    async def delete_role(self, role_id: str) -> dict:
        """Delete a role in PacketFence. DELETE /api/v1/config/role/{id}"""
        try:
            resp = await self._request("DELETE", f"/api/v1/config/role/{role_id}")
            logger.info(f"Role eliminado en PF: {role_id}, HTTP {resp.status_code}")
            if resp.content:
                return resp.json()
            return {"ok": True, "status": resp.status_code}
        except Exception as e:
            logger.warning(f"Error al eliminar role {role_id} en PF: {e}")
            return {"ok": False, "detail": str(e)[:200]}

    async def list_node_categories(self) -> list:
        """List node categories from PacketFence. GET /api/v1/node_categories"""
        resp = await self._request("GET", "/api/v1/node_categories")
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("items", [])

    async def get_category_id_for_role(self, role_name: str) -> Optional[int]:
        """Find the category_id (node_category) matching a role name."""
        categories = await self.list_node_categories()
        for cat in categories:
            if cat.get("name") == role_name:
                return int(cat.get("category_id", cat.get("id", 0)))
        return None

    async def create_pf_user(self, pid: str, email: str = "", firstname: str = "", lastname: str = "", category_id: Optional[int] = None) -> dict:
        """Create a user (person) in PacketFence. POST /api/v1/users"""
        payload = {"pid": pid}
        if email:
            payload["email"] = email
        if firstname:
            payload["firstname"] = firstname
        if lastname:
            payload["lastname"] = lastname
        if category_id is not None:
            payload["category_id"] = category_id
        resp = await self._request("POST", "/api/v1/users", json=payload)
        logger.info(f"Usuario PF creado: {pid}, HTTP {resp.status_code}")
        if resp.content:
            return resp.json()
        return {"ok": True, "status": resp.status_code}

    async def delete_pf_user(self, pid: str) -> dict:
        """Delete a user (person) in PacketFence. DELETE /api/v1/user/{pid}"""
        try:
            resp = await self._request("DELETE", f"/api/v1/user/{pid}")
            logger.info(f"Usuario PF eliminado: {pid}, HTTP {resp.status_code}")
            if resp.content:
                return resp.json()
            return {"ok": True, "status": resp.status_code}
        except Exception as e:
            logger.warning(f"Error al eliminar usuario PF {pid}: {e}")
            return {"ok": False, "detail": str(e)[:200]}

    async def list_profiles(self) -> list:
        """List available PKI profiles."""
        resp = await self._request("GET", "/api/v1/pki/profiles")
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("items", data.get("profiles", []))


async def get_pf_client(db: AsyncSession) -> PacketFenceClient:
    """Build a PacketFenceClient reading settings from DB with fallback to env vars."""
    from app.auth import decrypt_value
    from app.models import AppSetting

    async def _get(key: str, default: str = "") -> str:
        result = await db.execute(select(AppSetting).where(AppSetting.key == key))
        s = result.scalar_one_or_none()
        return s.value if s else default

    host = await _get("pf_host", settings.pf_host)
    username = await _get("pf_username", settings.pf_username)
    cert_profile = await _get("pf_cert_profile", settings.pf_cert_profile)
    verify_ssl = (await _get("pf_verify_ssl", str(settings.pf_verify_ssl))).lower() in ("true", "1", "yes")

    # Password is encrypted in DB
    raw_password = await _get("pf_password", "")
    if raw_password:
        try:
            password = decrypt_value(raw_password)
        except Exception:
            password = raw_password  # fallback si no esta cifrado
    else:
        password = settings.pf_password

    return PacketFenceClient(
        host=host,
        username=username,
        password=password,
        cert_profile=cert_profile,
        verify_ssl=verify_ssl,
    )
