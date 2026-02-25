import asyncio
import logging
import socket
import time
from typing import Optional
from urllib.parse import urlparse

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

    async def test_connection_detailed(self) -> list[dict]:
        """Test connection with step-by-step diagnostics.

        Returns a list of steps, each with:
          step, description, status (ok/error/skip), detail, elapsed_ms
        """
        steps: list[dict] = []

        # --- Paso 1: Parseo de URL ---
        t0 = time.monotonic()
        parsed = urlparse(self.host)
        host = parsed.hostname or parsed.path  # fallback if no scheme
        scheme = parsed.scheme or "https"
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        elapsed = round((time.monotonic() - t0) * 1000, 1)

        if host:
            steps.append({
                "step": 1,
                "description": "Parseo de URL",
                "status": "ok",
                "detail": f"Host: {host} | Puerto: {port} | Esquema: {scheme}",
                "elapsed_ms": elapsed,
            })
        else:
            steps.append({
                "step": 1,
                "description": "Parseo de URL",
                "status": "error",
                "detail": f"No se pudo extraer host de: {self.host}",
                "elapsed_ms": elapsed,
            })
            return steps

        # --- Paso 2: Resolucion DNS / IP ---
        t0 = time.monotonic()
        try:
            infos = await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            )
            resolved_ip = infos[0][4][0] if infos else "?"
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            steps.append({
                "step": 2,
                "description": "Resolucion DNS",
                "status": "ok",
                "detail": f"{host} -> {resolved_ip}",
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            steps.append({
                "step": 2,
                "description": "Resolucion DNS",
                "status": "error",
                "detail": f"No se pudo resolver {host}: {e}",
                "elapsed_ms": elapsed,
            })
            return steps

        # --- Paso 3: Conexion TCP ---
        t0 = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: sock.connect((resolved_ip, port))
            )
            sock.close()
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            steps.append({
                "step": 3,
                "description": "Conexion TCP",
                "status": "ok",
                "detail": f"Conexion exitosa a {resolved_ip}:{port}",
                "elapsed_ms": elapsed,
            })
        except Exception as e:
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            steps.append({
                "step": 3,
                "description": "Conexion TCP",
                "status": "error",
                "detail": f"No se pudo conectar a {resolved_ip}:{port}: {e}",
                "elapsed_ms": elapsed,
            })
            # Still try HTTP — maybe a proxy/firewall allows HTTP but not raw TCP
            steps.append({
                "step": 4,
                "description": "Login HTTP",
                "status": "skip",
                "detail": "Omitido por falla en conexion TCP",
                "elapsed_ms": 0,
            })
            steps.append({
                "step": 5,
                "description": "Validacion de token",
                "status": "skip",
                "detail": "Omitido por falla en conexion TCP",
                "elapsed_ms": 0,
            })
            return steps

        # --- Paso 4: Request HTTP POST /api/v1/login ---
        t0 = time.monotonic()
        try:
            async with self._client() as client:
                resp = await client.post(
                    f"{self.host}/api/v1/login",
                    json={"username": self.username, "password": self.password},
                )
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            body_preview = resp.text[:300] if resp.text else "(vacio)"

            if resp.status_code in (200, 201):
                steps.append({
                    "step": 4,
                    "description": "Login HTTP",
                    "status": "ok",
                    "detail": f"HTTP {resp.status_code} — Respuesta: {body_preview}",
                    "elapsed_ms": elapsed,
                })
                login_data = resp.json()
            else:
                steps.append({
                    "step": 4,
                    "description": "Login HTTP",
                    "status": "error",
                    "detail": f"HTTP {resp.status_code} — {body_preview}",
                    "elapsed_ms": elapsed,
                })
                steps.append({
                    "step": 5,
                    "description": "Validacion de token",
                    "status": "skip",
                    "detail": "Omitido por falla en login",
                    "elapsed_ms": 0,
                })
                return steps
        except Exception as e:
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            steps.append({
                "step": 4,
                "description": "Login HTTP",
                "status": "error",
                "detail": f"Error en request: {str(e)[:300]}",
                "elapsed_ms": elapsed,
            })
            steps.append({
                "step": 5,
                "description": "Validacion de token",
                "status": "skip",
                "detail": "Omitido por falla en login",
                "elapsed_ms": 0,
            })
            return steps

        # --- Paso 5: Validacion del token recibido ---
        t0 = time.monotonic()
        token = login_data.get("token") or login_data.get("access_token")
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        if token:
            steps.append({
                "step": 5,
                "description": "Validacion de token",
                "status": "ok",
                "detail": f"Token recibido ({len(token)} caracteres)",
                "elapsed_ms": elapsed,
            })
        else:
            steps.append({
                "step": 5,
                "description": "Validacion de token",
                "status": "error",
                "detail": f"No se encontro token en la respuesta. Keys: {list(login_data.keys())}",
                "elapsed_ms": elapsed,
            })

        return steps

    async def create_cert(self, cn: str, mail: str, password: str, profile_id: Optional[str] = None) -> dict:
        """Create a certificate in PacketFence.

        Two-step process:
          1. POST /api/v1/pki/certs  -> creates cert, returns JSON with ID
          2. GET  /api/v1/pki/cert/{ID}/download/p12  -> downloads the .p12 binary

        Returns dict with "p12_bytes" and "cert_id".
        """
        used_profile = str(profile_id or self.cert_profile)
        payload = {
            "cn": cn,
            "mail": mail,
            "profile_id": used_profile,
            "p12_password": password,
        }
        print(f"[PF-CERT] POST /api/v1/pki/certs payload={payload}")

        # Step 1: create the cert (profile_id must be a string)
        resp = await self._request("POST", "/api/v1/pki/certs", json=payload)

        print(f"[PF-CERT] Response HTTP {resp.status_code}")
        print(f"[PF-CERT] Response body: {resp.text[:1000]}")

        data = resp.json()
        items = data.get("items", [])
        if not items:
            # Log all keys and values for debugging
            raise ValueError(
                f"PacketFence no devolvio certificado. "
                f"HTTP={resp.status_code}, "
                f"profile_id={used_profile}, "
                f"keys={list(data.keys())}, "
                f"status={data.get('status')}, "
                f"message={data.get('message', '')}, "
                f"error={data.get('error', '')}, "
                f"body={resp.text[:500]}"
            )

        cert_id = str(items[0].get("ID", ""))
        if not cert_id:
            raise ValueError(f"PacketFence no devolvio ID de certificado. Keys: {list(items[0].keys())}")

        print(f"[PF-CERT] Certificado creado: ID={cert_id}, CN={cn}")

        # Step 2: download the .p12 binary
        print(f"[PF-CERT] GET /api/v1/pki/cert/{cert_id}/download/p12 ...")
        p12_resp = await self._request("GET", f"/api/v1/pki/cert/{cert_id}/download/p12")
        print(f"[PF-CERT] Download HTTP {p12_resp.status_code}, size={len(p12_resp.content)} bytes")

        if p12_resp.status_code != 200 or len(p12_resp.content) == 0:
            raise ValueError(f"No se pudo descargar el .p12 para cert ID {cert_id}. HTTP {p12_resp.status_code}, Size: {len(p12_resp.content)}")

        # Step 3: Re-package .p12 with our password
        # PacketFence may ignore the p12_password param and use its own,
        # so we re-encrypt with the password we want to give the user.
        p12_bytes = self._repackage_p12(p12_resp.content, password, original_password=password)

        return {"p12_bytes": p12_bytes, "cert_id": cert_id}

    @staticmethod
    def _repackage_p12(original_p12: bytes, new_password: str, original_password: str = "") -> bytes:
        """Re-encrypt a .p12 file with a new password.

        PacketFence may use its own password for the .p12 file, so we
        try common passwords to open it, then re-export with our password.
        Falls back to openssl CLI for legacy algorithm support.
        """
        import subprocess
        import tempfile
        from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption

        # Passwords to try: include the one we sent to PF first
        candidates = [
            original_password.encode() if original_password else b"",
            None, b"", b"secret", b"changeit", b"password", b"pfcert",
        ]

        private_key = None
        certificate = None
        cas = None
        last_error = ""

        for candidate in candidates:
            try:
                private_key, certificate, cas = pkcs12.load_key_and_certificates(
                    original_p12, candidate
                )
                print(f"[PF-CERT] p12 abierto con password (cryptography): {candidate!r}")
                break
            except Exception as e:
                last_error = f"{candidate!r} -> {type(e).__name__}: {str(e)[:150]}"
                continue

        if private_key is not None and certificate is not None:
            # Re-export with the desired password
            repackaged = pkcs12.serialize_key_and_certificates(
                name=None,
                key=private_key,
                cert=certificate,
                cas=cas,
                encryption_algorithm=BestAvailableEncryption(new_password.encode()),
            )
            print(f"[PF-CERT] p12 re-empaquetado con nueva password, size={len(repackaged)} bytes")
            return repackaged

        # cryptography library failed (likely legacy algorithms like RC2)
        # Fall back to openssl CLI which handles legacy formats
        print(f"[PF-CERT] cryptography no pudo abrir p12 (last: {last_error})")
        print(f"[PF-CERT] Intentando con openssl CLI...")

        for try_pass in [original_password, "", "secret", "changeit", "password"]:
            try:
                with tempfile.NamedTemporaryFile(suffix=".p12", delete=False) as f_in:
                    f_in.write(original_p12)
                    in_path = f_in.name
                with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f_pem:
                    pem_path = f_pem.name
                with tempfile.NamedTemporaryFile(suffix=".p12", delete=False) as f_out:
                    out_path = f_out.name

                # Extract to PEM (openssl handles legacy RC2 etc.)
                extract_cmd = [
                    "openssl", "pkcs12", "-in", in_path, "-out", pem_path,
                    "-nodes", "-passin", f"pass:{try_pass}",
                ]
                result = subprocess.run(extract_cmd, capture_output=True, timeout=10)
                if result.returncode != 0:
                    print(f"[PF-CERT] openssl extract failed with pass={try_pass!r}: {result.stderr.decode()[:200]}")
                    continue

                print(f"[PF-CERT] openssl extract OK con pass={try_pass!r}")

                # Re-export as .p12 with our password
                export_cmd = [
                    "openssl", "pkcs12", "-export",
                    "-in", pem_path, "-out", out_path,
                    "-passout", f"pass:{new_password}",
                ]
                result = subprocess.run(export_cmd, capture_output=True, timeout=10)
                if result.returncode != 0:
                    print(f"[PF-CERT] openssl export failed: {result.stderr.decode()[:200]}")
                    continue

                with open(out_path, "rb") as f:
                    repackaged = f.read()
                print(f"[PF-CERT] p12 re-empaquetado via openssl, size={len(repackaged)} bytes")
                return repackaged
            except Exception as e:
                print(f"[PF-CERT] openssl attempt failed (pass={try_pass!r}): {e}")
            finally:
                import os
                for p in [in_path, pem_path, out_path]:
                    try:
                        os.unlink(p)
                    except Exception:
                        pass

        print("[PF-CERT] WARNING: No se pudo re-empaquetar el p12 por ningun metodo")
        return original_p12

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
