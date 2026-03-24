"""Control plane API client."""

import json
import logging
from base64 import b64decode
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from .config import settings

logger = logging.getLogger(__name__)

HKDF_SALT = b"vpn-mcp-node-encrypt"
HKDF_INFO = b"v1"


class Credentials:
    def __init__(self, control_plane_url: str, client_id: str, api_key: str):
        self.control_plane_url = control_plane_url
        self.client_id = client_id
        self.api_key = api_key

    def save(self, path: Path | None = None):
        path = path or settings.credentials_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"control_plane_url": self.control_plane_url, "client_id": self.client_id, "api_key": self.api_key},
                indent=2,
            )
        )

    @classmethod
    def load(cls, path: Path | None = None) -> "Credentials | None":
        path = path or settings.credentials_path
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        return cls(data["control_plane_url"], data["client_id"], data["api_key"])


def _derive_key(api_key: str) -> bytes:
    """Derive AES-256 key from API key via HKDF-SHA256."""
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=HKDF_SALT, info=HKDF_INFO)
    return hkdf.derive(api_key.encode())


def _decrypt_response(encrypted_b64: str, api_key: str) -> dict:
    """Decrypt an AES-256-GCM encrypted API response."""
    raw = b64decode(encrypted_b64)
    key = _derive_key(api_key)
    gcm = AESGCM(key)
    # Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
    nonce = raw[:12]
    ciphertext = raw[12:]
    plaintext = gcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)


class ControlPlaneClient:
    def __init__(self, creds: Credentials):
        self.creds = creds
        self.base_url = creds.control_plane_url.rstrip("/")
        self.http = httpx.Client(
            timeout=15.0,
            headers={"Authorization": f"Bearer {creds.api_key}"},
        )

    def status(self) -> dict:
        resp = self.http.get(f"{self.base_url}/api/mcp/status")
        resp.raise_for_status()
        return resp.json()

    def nodes(self) -> list[dict]:
        resp = self.http.get(f"{self.base_url}/api/mcp/nodes")
        resp.raise_for_status()
        data = resp.json()
        if "encrypted" in data:
            decrypted = _decrypt_response(data["encrypted"], self.creds.api_key)
            return decrypted.get("nodes", [])
        return data.get("nodes", [])

    def connect(self, node_id: str = "") -> dict:
        body = {"node_id": node_id} if node_id else {}
        resp = self.http.post(f"{self.base_url}/api/mcp/connect", json=body)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            return data
        if "encrypted" in data:
            return _decrypt_response(data["encrypted"], self.creds.api_key)
        return data

    @staticmethod
    def register(control_plane_url: str) -> dict:
        """Register a new MCP client (no auth needed). Sends machine fingerprint for dedup."""
        from .fingerprint import get_machine_fingerprint

        body = {"machine_fingerprint": get_machine_fingerprint()}
        resp = httpx.post(f"{control_plane_url.rstrip('/')}/api/mcp/register", json=body, timeout=15.0)
        resp.raise_for_status()
        return resp.json()
