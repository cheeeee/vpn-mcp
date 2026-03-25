"""Control plane API client."""

import json
import logging
import time
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

MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds multiplier


class RateLimitError(Exception):
    """Raised when the server returns 429 Too Many Requests."""

    def __init__(self, message: str, retry_after: int = 0, remaining: int = 0, limit: int = 60):
        super().__init__(message)
        self.retry_after = retry_after
        self.remaining = remaining
        self.limit = limit


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


def _check_rate_limit(resp: httpx.Response) -> None:
    """Check response for rate limit and raise descriptive error if hit."""
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "60"))
        remaining = int(resp.headers.get("X-RateLimit-Remaining", "0"))
        limit = int(resp.headers.get("X-RateLimit-Limit", "60"))

        try:
            body = resp.json()
            msg = body.get("error", "Rate limited")
        except Exception:
            msg = resp.text or "Rate limited"

        raise RateLimitError(
            f"{msg} (limit: {limit}/min, remaining: {remaining}, retry in {retry_after}s)",
            retry_after=retry_after,
            remaining=remaining,
            limit=limit,
        )


def _request_with_retry(method: str, url: str, client: httpx.Client | None = None, **kwargs) -> httpx.Response:
    """Make an HTTP request with automatic retry on rate limit (429)."""
    http = client or httpx.Client(timeout=15.0)
    should_close = client is None

    try:
        for attempt in range(MAX_RETRIES):
            if method == "GET":
                resp = http.get(url, **kwargs)
            elif method == "POST":
                resp = http.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", str(RETRY_BACKOFF * (attempt + 1))))
                remaining_attempts = MAX_RETRIES - attempt - 1
                if remaining_attempts > 0:
                    logger.warning(
                        "Rate limited (429), retrying in %ds (%d attempts left)", retry_after, remaining_attempts
                    )
                    time.sleep(retry_after)
                    continue
                else:
                    _check_rate_limit(resp)

            return resp
    finally:
        if should_close:
            http.close()

    return resp  # unreachable but satisfies type checker


class ControlPlaneClient:
    def __init__(self, creds: Credentials):
        self.creds = creds
        self.base_url = creds.control_plane_url.rstrip("/")
        self.http = httpx.Client(
            timeout=15.0,
            headers={"Authorization": f"Bearer {creds.api_key}"},
        )

    def _get(self, path: str) -> httpx.Response:
        """GET with rate limit retry."""
        return _request_with_retry("GET", f"{self.base_url}{path}", client=self.http)

    def _post(self, path: str, **kwargs) -> httpx.Response:
        """POST with rate limit retry."""
        return _request_with_retry("POST", f"{self.base_url}{path}", client=self.http, **kwargs)

    def status(self) -> dict:
        resp = self._get("/api/mcp/status")
        resp.raise_for_status()
        return resp.json()

    def nodes(self) -> list[dict]:
        resp = self._get("/api/mcp/nodes")
        resp.raise_for_status()
        data = resp.json()
        if "encrypted" in data:
            decrypted = _decrypt_response(data["encrypted"], self.creds.api_key)
            return decrypted.get("nodes", [])
        return data.get("nodes", [])

    def connect(self, node_id: str = "") -> dict:
        body = {"node_id": node_id} if node_id else {}
        resp = self._post("/api/mcp/connect", json=body)
        if resp.status_code == 402:
            return resp.json()  # quota_exceeded with details
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
        resp = _request_with_retry(
            "POST", f"{control_plane_url.rstrip('/')}/api/mcp/register", json=body, timeout=15.0
        )
        _check_rate_limit(resp)
        resp.raise_for_status()
        return resp.json()
