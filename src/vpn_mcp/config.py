import os
from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    control_plane_url: str = os.environ.get("VPN_CONTROL_PLANE_URL", "https://api.vpn-mcp.net")
    credentials_path: Path = Path.home() / ".vpn-mcp" / "credentials.json"
    xray_binary: str = os.environ.get("XRAY_BINARY", "")
    bin_dir: Path = Path.home() / ".vpn-mcp" / "bin"
    http_proxy_port: int = int(os.environ.get("VPN_HTTP_PROXY_PORT", "18080"))
    socks_proxy_port: int = int(os.environ.get("VPN_SOCKS_PROXY_PORT", "18081"))
    pac_file_path: Path = Path.home() / ".vpn-mcp" / "proxy.pac"


settings = Settings()
