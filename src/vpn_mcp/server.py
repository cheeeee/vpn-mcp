"""VPN MCP server — Internet access for AI coding tools through VPN exit nodes."""

import logging
import platform
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .client import ControlPlaneClient, Credentials
from .config import settings
from .proxy import (
    ManagedProxy,
    XrayProxy,
    download_xray,
    generate_pac_file,
    generate_xray_config,
    get_xray_binary,
    XRAY_VERSION,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)

UPGRADE_MESSAGE = (
    "Upgrade for faster access:\n"
    "  1 USDT/mo Basic: 30 req/min, 500 KB/s, all exit nodes\n"
    "  5 USDT/mo Pro: 120 req/min, 2 MB/s, all exit nodes + Tor\n"
    "\nVisit https://vpn-mcp.net/setup for details."
)

server = Server("vpn-mcp")
xray_proxy = XrayProxy()
managed_proxy = ManagedProxy(settings.http_proxy_port, settings.socks_proxy_port)


# Start the managed proxy immediately — it runs in passthrough mode by default.
# In "full proxy" mode (HTTPS_PROXY set), WebFetch routes through this proxy.
# In default mode, use vpn_fetch() tool for explicit VPN requests.
try:
    managed_proxy.start()
except OSError as e:
    logger.warning("Could not start managed proxy on port %d: %s", settings.http_proxy_port, e)


def _get_creds() -> Credentials | None:
    return Credentials.load()


def _get_client() -> ControlPlaneClient | None:
    creds = _get_creds()
    if creds is None:
        return None
    return ControlPlaneClient(creds)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="vpn_connect",
            description=(
                "Connect to a VPN exit node. Starts local proxy. "
                "After connecting, use vpn_fetch(url) to make requests through the VPN. "
                "If the account is not yet activated, returns payment instructions — "
                "show these to the user so they can pay with a TON wallet app. "
                "Do NOT open a browser for payment — the payment address is returned directly by this tool."
            ),
            inputSchema={
                "type": "object",
                "properties": {"node": {"type": "string", "description": "Exit node ID (e.g. 'na-1'). Optional."}},
            },
        ),
        Tool(
            name="vpn_disconnect",
            description="Disconnect from VPN. Stops the local proxy. WebFetch returns to direct connection.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="vpn_switch",
            description="Switch to a different VPN exit node. Restarts the proxy with the new node.",
            inputSchema={
                "type": "object",
                "properties": {"node": {"type": "string", "description": "Exit node ID to switch to."}},
                "required": ["node"],
            },
        ),
        Tool(
            name="vpn_status",
            description=(
                "Check VPN account status: payment state, quota used/remaining, expiry, active node. "
                "Use after payment to verify activation before connecting."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="vpn_nodes",
            description="List available VPN exit nodes with regions. Requires an active (paid) account.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="vpn_activate",
            description=(
                "Activate VPN account. Returns a TON USDT payment address and instructions. "
                "Show the address and instructions to the user — they need to send 1 USDT "
                "using a TON wallet app (Tonkeeper, TonHub, etc). Payment is detected automatically. "
                "Do NOT open a browser — all payment info is returned by this tool. "
                "After the user pays, call vpn_status() to check, then vpn_connect() to start."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="vpn_fetch",
            description=(
                "Fetch a URL through the VPN tunnel. Use this instead of WebFetch when you need "
                "the request to come from the VPN exit node IP. Requires vpn_connect() first. "
                "Returns status code, headers, and body. This is the safe default — "
                "only vpn_fetch requests go through VPN, WebFetch stays direct."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "method": {"type": "string", "description": "HTTP method (GET, POST, etc). Default: GET."},
                    "headers": {
                        "type": "object",
                        "description": "Optional HTTP headers as key-value pairs.",
                        "additionalProperties": {"type": "string"},
                    },
                    "body": {"type": "string", "description": "Optional request body."},
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="vpn_setup",
            description="Download and install VPN binary for the current OS. Called automatically by vpn_connect if needed.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "vpn_connect":
            return [TextContent(type="text", text=_handle_connect(arguments.get("node", "")))]
        elif name == "vpn_disconnect":
            return [TextContent(type="text", text=_handle_disconnect())]
        elif name == "vpn_switch":
            return [TextContent(type="text", text=_handle_connect(arguments["node"]))]
        elif name == "vpn_status":
            return [TextContent(type="text", text=_handle_status())]
        elif name == "vpn_nodes":
            return [TextContent(type="text", text=_handle_nodes())]
        elif name == "vpn_activate":
            return [TextContent(type="text", text=_handle_activate())]
        elif name == "vpn_fetch":
            return [TextContent(type="text", text=_handle_fetch(arguments))]
        elif name == "vpn_setup":
            return [TextContent(type="text", text=_handle_setup())]
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return [TextContent(type="text", text=f"Error: {e}")]


def _payment_instructions(address: str, amount: str = "1", network: str = "TON") -> str:
    """Format clear payment instructions for the user."""
    return (
        f"To activate VPN MCP, send {amount} USDT on the {network} network to:\n\n"
        f"  {address}\n\n"
        f"How to pay:\n"
        f"  1. Open a TON wallet app (Tonkeeper, TonHub, MyTonWallet, or any TON wallet)\n"
        f"  2. Send {amount} USDT (not TON) to the address above\n"
        f"  3. Payment is detected automatically within 30 seconds\n\n"
        f"Or visit https://vpn-mcp.net/setup for the full setup guide.\n\n"
        f"Pricing: {amount} USDT = 1 GB/month, all exit nodes. Quota resets every 30 days.\n\n"
        f"After payment, call vpn_connect() to start using the VPN."
    )


def _handle_connect(node_id: str) -> str:
    creds = _get_creds()
    if creds is None:
        return _handle_activate()

    client = ControlPlaneClient(creds)

    # Check account status.
    status_resp = client.status()
    status = status_resp.get("status")

    if status == "pending_payment":
        payment = status_resp.get("payment", {})
        return _payment_instructions(
            payment.get("address", "unknown"), payment.get("amount", "1"), payment.get("network", "TON")
        )

    if status == "expired":
        return "Account expired. Call vpn_activate() to purchase again."

    if status == "quota_exceeded":
        quota = status_resp.get("quota", {})
        return (
            f"Quota exceeded ({quota.get('used_bytes', 0) // (1024**3)}GB / "
            f"{quota.get('limit_bytes', 0) // (1024**3)}GB). Call vpn_activate() to purchase more."
        )

    if status != "active":
        return f"Account status: {status}. Call vpn_activate() if you need a new account."

    # Ensure xray binary is installed.
    try:
        get_xray_binary()
    except RuntimeError:
        download_xray()

    # Connect to node.
    connect_resp = client.connect(node_id)
    if "error" in connect_resp:
        if connect_resp["error"] == "quota_exceeded":
            quota = connect_resp.get("quota", {})
            return f"Quota exceeded ({quota.get('percent', 100)}%). Call vpn_activate() to purchase more."
        return f"Connection error: {connect_resp['error']}"

    vless = connect_resp.get("vless", {})
    ws = connect_resp.get("ws")

    if ws:
        # Prefer WebSocket transport (direct to node IP, TLS with LE cert).
        config = generate_xray_config(
            node_ip=ws["address"],
            node_port=ws.get("port", 443),
            uuid=connect_resp["xray_uuid"],
            flow="",
            ws_path=ws["path"],
            ws_host=ws.get("host", ""),
        )
    else:
        # Fallback to Reality transport.
        config = generate_xray_config(
            node_ip=vless["address"],
            node_port=vless["port"],
            uuid=connect_resp["xray_uuid"],
            flow=vless.get("flow", "xtls-rprx-vision"),
            reality_public_key=vless["reality_public_key"],
            reality_short_id=vless["reality_short_id"],
            reality_sni=vless.get("reality_sni", "dl.google.com"),
        )

    xray_proxy.start(config, connect_resp.get("node_id", node_id))
    managed_proxy.set_mode("tunnel")
    pac_path = generate_pac_file()

    # Build response with quota warning if applicable.
    quota = connect_resp.get("quota", {})
    warning = connect_resp.get("warning") or ""
    quota_line = f"Quota: {quota.get('used_bytes', 0) // (1024**3)}GB / {quota.get('limit_bytes', 0) // (1024**3)}GB"

    lines = [
        f"Connected to {connect_resp.get('node_id', 'unknown')}. Use vpn_fetch(url) to make requests through VPN.",
        "",
        f"  {quota_line}",
        "",
        "Browser/apps:",
        f"  HTTP proxy:   127.0.0.1:{settings.http_proxy_port}",
        f"  SOCKS5 proxy: 127.0.0.1:{settings.socks_proxy_port}",
        f"  PAC file:     {pac_path}",
        "",
        "To use in your browser, set auto-config proxy URL to:",
        f"  file://{pac_path}",
    ]
    if warning:
        lines.insert(1, f"\n{warning}")
    return "\n".join(lines)


def _handle_disconnect() -> str:
    if not xray_proxy.running:
        return "Not connected."
    xray_proxy.stop()
    managed_proxy.set_mode("direct")
    return "Disconnected. WebFetch now uses direct connection."


def _handle_status() -> str:
    client = _get_client()
    if client is None:
        return "No VPN account configured. Call vpn_activate() to register."

    resp = client.status()
    status = resp.get("status", "unknown")
    quota = resp.get("quota", {})
    connected = "yes" if xray_proxy.running else "no"

    resets_at = quota.get("resets_at", 0)
    reset_info = ""
    if resets_at > 0:
        import time as _time

        days_left = max(0, (resets_at - int(_time.time())) // 86400)
        reset_info = f" (resets in {days_left} days)"

    lines = [
        f"Status: {status}",
        f"Connected: {connected} (node: {xray_proxy.current_node or 'none'})",
        f"Quota: {quota.get('used_bytes', 0) // (1024**3)}GB / {quota.get('limit_bytes', 0) // (1024**3)}GB ({quota.get('percent', 0)}%){reset_info}",
        f"Expires: {quota.get('expires_at', 'unknown')}",
    ]

    # Show available nodes for active accounts.
    if status == "active":
        try:
            nodes = client.nodes()
            if nodes:
                lines.append("")
                lines.append("Exit nodes:")
                for n in nodes:
                    marker = " <--" if n["id"] == (xray_proxy.current_node or "") else ""
                    lines.append(f"  {n['id']:10s} {n['name']}{marker}")
        except Exception:
            pass

    if status == "pending_payment":
        payment = resp.get("payment", {})
        lines.append(f"\nPayment pending. Send {payment.get('amount', '1')} USDT to: {payment.get('address', '')}")

    return "\n".join(lines)


def _handle_nodes() -> str:
    client = _get_client()
    if client is None:
        return "No VPN account configured. Call vpn_activate() to register."

    nodes = client.nodes()
    if not nodes:
        return "No exit nodes available."

    lines = ["Available exit nodes:", ""]
    for n in nodes:
        lines.append(f"  {n['id']:10s} {n['name']:30s} ({n['region']})")
    return "\n".join(lines)


def _handle_activate() -> str:
    creds = _get_creds()

    # If already registered, check status.
    if creds:
        client = ControlPlaneClient(creds)
        resp = client.status()
        status = resp.get("status")
        if status == "active":
            return "Account already active. Use vpn_connect() to connect."
        if status == "pending_payment":
            payment = resp.get("payment", {})
            return _payment_instructions(
                payment.get("address", "unknown"), payment.get("amount", "1"), payment.get("network", "TON")
            )

    # Register new account (free, instant — sends machine fingerprint for dedup).
    resp = ControlPlaneClient.register(settings.control_plane_url)

    # Save credentials.
    creds = Credentials(
        control_plane_url=settings.control_plane_url,
        client_id=resp["client_id"],
        api_key=resp["api_key"],
    )
    creds.save()

    tier = resp.get("tier", "free")
    if tier == "free":
        payment = resp.get("payment", {})
        address = payment.get("address", "")
        msg = (
            f"VPN MCP account activated (free tier). Credentials saved to {settings.credentials_path}\n\n"
            f"Free tier: 1 request per 30 seconds, 256 KB/s bandwidth.\n\n"
            f"{UPGRADE_MESSAGE}\n"
        )
        if address:
            msg += f"\nSend USDT on TON to: {address}\nDetails: https://vpn-mcp.net/setup\n"
        msg += "\nCall vpn_connect() to start using the VPN."
        return msg

    payment = resp.get("payment", {})
    return f"VPN MCP account created. API key saved to {settings.credentials_path}\n\n" + _payment_instructions(
        payment.get("address", "unknown"), payment.get("amount", "1"), payment.get("network", "TON")
    )


def _handle_fetch(args: dict) -> str:
    """Fetch a URL through the VPN proxy."""
    if not xray_proxy.running:
        return "Error: VPN not connected. Call vpn_connect() first."

    url = args.get("url", "")
    method = args.get("method", "GET").upper()
    headers = args.get("headers") or {}
    body = args.get("body")

    try:
        import httpx as _httpx

        # Use the managed HTTP CONNECT proxy (not SOCKS5 directly).
        # httpx SOCKS5 + HTTPS has TLS issues with xray's xtls-rprx-vision flow.
        # The managed proxy handles the SOCKS5 tunnel internally with raw sockets.
        proxy_url = f"http://127.0.0.1:{settings.http_proxy_port}"
        with _httpx.Client(proxy=proxy_url, timeout=30.0, follow_redirects=True) as client:
            resp = client.request(method, url, headers=headers, content=body.encode() if body else None)

        # Format response
        lines = [f"HTTP {resp.status_code} {resp.reason_phrase}", ""]

        # Selected response headers
        for key in ("content-type", "content-length", "location", "server"):
            if key in resp.headers:
                lines.append(f"{key}: {resp.headers[key]}")
        lines.append("")

        # Body (truncated to 100KB)
        content_type = resp.headers.get("content-type", "")
        if "text" in content_type or "json" in content_type or "xml" in content_type:
            text = resp.text[:102400]
            if len(resp.text) > 102400:
                text += f"\n\n... (truncated, {len(resp.text)} bytes total)"
            lines.append(text)
        else:
            lines.append(f"[Binary content: {len(resp.content)} bytes, type: {content_type}]")

        return "\n".join(lines)
    except Exception as e:
        error_msg = str(e)
        # Detect xray connection rate limit rejection
        if "rate limit" in error_msg.lower():
            return (
                "RATE LIMITED: You've exceeded your request limit.\n\n"
                "Free tier: 1 request per 30 seconds.\n\n"
                f"{UPGRADE_MESSAGE}"
            )
        return f"Error fetching {url}: {e}"


def _handle_setup() -> str:
    try:
        binary = get_xray_binary()
        if binary.exists():
            return f"VPN binary already installed at {binary}"
    except RuntimeError:
        pass

    binary = download_xray()
    return f"xray {XRAY_VERSION} installed at {binary} ({platform.system()}/{platform.machine()})"


def main():
    import asyncio

    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(run())


if __name__ == "__main__":
    main()
