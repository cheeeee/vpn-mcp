"""xray subprocess management, PAC file generation, and HTTP CONNECT proxy."""

import json
import logging
import platform
import shutil
import socket
import stat
import subprocess
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx

from .config import settings

logger = logging.getLogger(__name__)

XRAY_VERSION = "v26.2.6"
GITHUB_RELEASE_URL = f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}"

PLATFORM_MAP = {
    ("Linux", "x86_64"): "Xray-linux-64.zip",
    ("Linux", "aarch64"): "Xray-linux-arm64-v8a.zip",
    ("Darwin", "x86_64"): "Xray-macos-64.zip",
    ("Darwin", "arm64"): "Xray-macos-arm64-v8a.zip",
    ("Windows", "AMD64"): "Xray-windows-64.zip",
    ("Windows", "ARM64"): "Xray-windows-arm64-v8a.zip",
}


def get_binary_name() -> str:
    return "xray.exe" if platform.system() == "Windows" else "xray"


def get_xray_binary() -> Path:
    """Find or download xray binary."""
    if settings.xray_binary:
        p = Path(settings.xray_binary)
        if p.exists():
            return p

    cached = settings.bin_dir / get_binary_name()
    if cached.exists():
        return cached

    return download_xray()


def download_xray() -> Path:
    """Download xray from GitHub releases for the current platform."""
    key = (platform.system(), platform.machine())
    asset = PLATFORM_MAP.get(key)
    if not asset:
        raise RuntimeError(f"Unsupported platform: {platform.system()} {platform.machine()}")

    settings.bin_dir.mkdir(parents=True, exist_ok=True)
    url = f"{GITHUB_RELEASE_URL}/{asset}"

    logger.info("Downloading xray %s from %s", XRAY_VERSION, url)
    with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as resp:
        resp.raise_for_status()
        tmp = settings.bin_dir / f"{asset}.tmp"
        with open(tmp, "wb") as f:
            for chunk in resp.iter_bytes(8192):
                f.write(chunk)

    # Extract xray binary from zip.
    binary_name = get_binary_name()
    dest = settings.bin_dir / binary_name
    with zipfile.ZipFile(tmp) as zf:
        for name in zf.namelist():
            if name.lower() == binary_name.lower():
                with zf.open(name) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                break
        else:
            raise RuntimeError(f"{binary_name} not found in {asset}")

    tmp.unlink(missing_ok=True)

    if platform.system() != "Windows":
        dest.chmod(dest.stat().st_mode | stat.S_IEXEC)

    logger.info("Installed xray %s at %s", XRAY_VERSION, dest)
    return dest


def generate_xray_config(
    node_ip: str, node_port: int, uuid: str, flow: str, reality_public_key: str, reality_short_id: str, reality_sni: str
) -> dict:
    """Generate xray JSON config with SOCKS5 inbound and VLESS+Reality outbound.

    The MCP server runs its own HTTP CONNECT proxy on http_proxy_port.
    xray only needs SOCKS5 for the MCP proxy to tunnel through.
    """
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": settings.socks_proxy_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": node_ip,
                            "port": node_port,
                            "users": [{"id": uuid, "flow": flow, "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": reality_sni,
                        "publicKey": reality_public_key,
                        "shortId": reality_short_id,
                        "fingerprint": "chrome",
                    },
                },
            }
        ],
    }


def generate_pac_file() -> Path:
    """Generate proxy auto-config file for browser use."""
    pac_content = f"""function FindProxyForURL(url, host) {{
    if (isPlainHostName(host) || host === "localhost"
        || host.startsWith("127.") || host.startsWith("192.168.")
        || host.startsWith("10.") || host.endsWith(".local")) {{
        return "DIRECT";
    }}
    return "PROXY 127.0.0.1:{settings.http_proxy_port}; DIRECT";
}}
"""
    settings.pac_file_path.parent.mkdir(parents=True, exist_ok=True)
    settings.pac_file_path.write_text(pac_content)
    return settings.pac_file_path


class XrayProxy:
    """Manages a local xray subprocess that provides HTTP + SOCKS5 proxy."""

    def __init__(self):
        self.process: subprocess.Popen | None = None
        self.config_path: Path | None = None
        self.current_node: str | None = None

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self, config: dict, node_id: str) -> None:
        """Start xray with the given config."""
        if self.running:
            self.stop()

        xray_binary = get_xray_binary()

        # Write config to temp file.
        config_dir = Path.home() / ".vpn-mcp"
        config_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = config_dir / "xray-config.json"
        self.config_path.write_text(json.dumps(config, indent=2))

        # Start xray subprocess.
        creation_flags = 0
        if platform.system() == "Windows":
            creation_flags = subprocess.CREATE_NO_WINDOW

        self.process = subprocess.Popen(
            [str(xray_binary), "run", "-c", str(self.config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
        )
        self.current_node = node_id

        # Wait for proxy to be ready.
        self._wait_for_proxy()
        logger.info("xray started (pid=%d, node=%s)", self.process.pid, node_id)

    def stop(self) -> None:
        """Stop the xray subprocess."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
            logger.info("xray stopped")
            self.process = None
            self.current_node = None

        if self.config_path and self.config_path.exists():
            self.config_path.unlink(missing_ok=True)

    def _wait_for_proxy(self, timeout: float = 10.0) -> None:
        """Wait for the SOCKS5 proxy port to accept connections."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process and self.process.poll() is not None:
                stderr = self.process.stderr.read().decode() if self.process.stderr else ""
                raise RuntimeError(f"xray exited with code {self.process.returncode}: {stderr[:500]}")
            try:
                with socket.create_connection(("127.0.0.1", settings.socks_proxy_port), timeout=0.5):
                    return
            except (ConnectionRefusedError, OSError):
                time.sleep(0.3)
        raise TimeoutError(f"xray SOCKS5 proxy not ready after {timeout}s")


class ManagedProxy:
    """HTTP CONNECT proxy that runs as a background thread.

    Starts in passthrough mode (direct connections).
    Switches to tunnel mode when xray is running (routes through SOCKS5).
    """

    # Domains that always bypass the VPN tunnel (go direct even in tunnel mode).
    # Prevents Anthropic API calls from being routed through exit nodes that may be blocked.
    BYPASS_DOMAINS = [
        ".anthropic.com",
        "claude.ai",
        ".claude.ai",
        "sentry.io",
        ".sentry.io",
        ".statsig.com",
        ".launchdarkly.com",
    ]

    def __init__(self, listen_port: int, socks_port: int):
        self.listen_port = listen_port
        self.socks_port = socks_port
        self._mode = "direct"  # "direct" or "tunnel"
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        logger.info("Proxy mode: %s", mode)

    def start(self) -> None:
        """Start the proxy server in a background thread."""
        proxy_ref = self

        class ProxyHandler(BaseHTTPRequestHandler):
            def _should_bypass(self, host: str) -> bool:
                """Check if host should bypass VPN and go direct."""
                for domain in ManagedProxy.BYPASS_DOMAINS:
                    if domain.startswith("."):
                        if host.endswith(domain) or host == domain[1:]:
                            return True
                    elif host == domain:
                        return True
                return False

            def do_CONNECT(self):
                """Handle HTTPS tunneling via CONNECT method."""
                host, port_str = self.path.split(":")
                port = int(port_str)
                try:
                    if proxy_ref.mode == "tunnel" and not self._should_bypass(host):
                        remote = self._connect_via_socks(host, port)
                    else:
                        remote = socket.create_connection((host, port), timeout=10)

                    self.send_response(200, "Connection established")
                    self.end_headers()

                    self._tunnel(self.connection, remote)
                except Exception as e:
                    self.send_error(502, f"Proxy error: {e}")

            def do_GET(self):
                self._proxy_http()

            def do_POST(self):
                self._proxy_http()

            def do_PUT(self):
                self._proxy_http()

            def do_DELETE(self):
                self._proxy_http()

            def _proxy_http(self):
                """Proxy plain HTTP requests."""
                import urllib.request

                try:
                    body = None
                    if "Content-Length" in self.headers:
                        body = self.rfile.read(int(self.headers["Content-Length"]))

                    req = urllib.request.Request(self.path, data=body, method=self.command)
                    for key, val in self.headers.items():
                        if key.lower() not in ("host", "proxy-connection"):
                            req.add_header(key, val)

                    if proxy_ref.mode == "tunnel":
                        proxy_handler = urllib.request.ProxyHandler(
                            {
                                "http": f"socks5://127.0.0.1:{proxy_ref.socks_port}",
                                "https": f"socks5://127.0.0.1:{proxy_ref.socks_port}",
                            }
                        )
                        opener = urllib.request.build_opener(proxy_handler)
                    else:
                        opener = urllib.request.build_opener()

                    resp = opener.open(req, timeout=30)
                    self.send_response(resp.status)
                    for key, val in resp.headers.items():
                        self.send_header(key, val)
                    self.end_headers()
                    self.wfile.write(resp.read())
                except Exception as e:
                    self.send_error(502, str(e))

            def _connect_via_socks(self, host: str, port: int) -> socket.socket:
                """Connect to target via SOCKS5 proxy."""
                sock = socket.create_connection(("127.0.0.1", proxy_ref.socks_port), timeout=10)
                # SOCKS5 handshake
                sock.sendall(b"\x05\x01\x00")  # version 5, 1 method, no auth
                resp = sock.recv(2)
                if resp != b"\x05\x00":
                    raise RuntimeError("SOCKS5 handshake failed")

                # SOCKS5 connect request
                addr = host.encode()
                sock.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + port.to_bytes(2, "big"))
                resp = sock.recv(10)
                if resp[1] != 0:
                    raise RuntimeError(f"SOCKS5 connect failed: status {resp[1]}")
                return sock

            def _tunnel(self, client: socket.socket, remote: socket.socket) -> None:
                """Bidirectional tunnel between client and remote sockets."""
                import select

                sockets = [client, remote]
                try:
                    while True:
                        readable, _, exceptional = select.select(sockets, [], sockets, 120)
                        if exceptional:
                            break
                        for s in readable:
                            data = s.recv(65536)
                            if not data:
                                return
                            target = remote if s is client else client
                            target.sendall(data)
                finally:
                    remote.close()

            def log_message(self, format, *args):
                pass  # Suppress request logging

        self._server = HTTPServer(("127.0.0.1", self.listen_port), ProxyHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("Managed proxy started on 127.0.0.1:%d (mode: %s)", self.listen_port, self._mode)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        self._thread = None
        logger.info("Managed proxy stopped")
