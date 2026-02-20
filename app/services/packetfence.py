import ssl
from typing import Optional

import httpx

from app.config import settings


class PacketFenceClient:
    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cert_profile: Optional[str] = None,
    ):
        self.host = (host or settings.pf_host).rstrip("/")
        self.username = username or settings.pf_username
        self.password = password or settings.pf_password
        self.cert_profile = cert_profile or settings.pf_cert_profile
        self._token: Optional[str] = None

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(verify=False, timeout=30.0)

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

    async def create_cert(self, cn: str, password: str) -> bytes:
        """Create a certificate in PacketFence and return the .p12 bytes."""
        resp = await self._request(
            "POST",
            f"/api/v1/pki/certs",
            json={
                "cn": cn,
                "mail": f"{cn}@cert.local",
                "profile_name": self.cert_profile,
                "p12_password": password,
            },
        )
        resp.raise_for_status()

        # PF puede devolver el p12 como binario o como base64 dentro del JSON
        content_type = resp.headers.get("content-type", "")
        if "application/json" in content_type:
            import base64
            data = resp.json()
            p12_b64 = data.get("p12") or data.get("certificate") or data.get("cert")
            if p12_b64:
                return base64.b64decode(p12_b64)
            raise ValueError(f"Respuesta inesperada de PacketFence: {list(data.keys())}")
        return resp.content

    async def revoke_cert(self, cert_id: str, reason: int = 2) -> dict:
        """Revoke a certificate. reason=2 is 'cessationOfOperation'."""
        resp = await self._request(
            "DELETE",
            f"/api/v1/pki/cert/{cert_id}",
            json={"reason": reason},
        )
        resp.raise_for_status()
        return resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"ok": True}

    async def list_profiles(self) -> list:
        """List available PKI profiles."""
        resp = await self._request("GET", "/api/v1/pki/profiles")
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("items", data.get("profiles", []))
