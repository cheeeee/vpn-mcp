# vpn-mcp

Internet access for AI coding tools through VPN exit nodes.

An [MCP](https://modelcontextprotocol.io/) server that gives your AI coding assistant access to the internet through VPN exit nodes. Route requests through different regions, bypass geo-restrictions, avoid rate limits.

Works with **Claude Code**, **Cursor**, **Windsurf**, **OpenCode**, **Cline**, **Continue**, **Zed**, **Hermes**, and any MCP-compatible client.

## Quick start

```bash
# Install
uv tool install vpn-mcp

# Or with pip
pip install vpn-mcp
```

Add to your MCP config (`.mcp.json` for Claude Code, `.cursor/mcp.json` for Cursor, etc.):

```json
{
  "mcpServers": {
    "vpn": {
      "command": "vpn-mcp"
    }
  }
}
```

Then from your AI assistant:

```
> vpn_activate()
Account activated — Free tier

> vpn_connect()
Connected to North America

> vpn_fetch("https://httpbin.org/ip")
{"origin": "185.xx.xx.xx"}
```

## Features

- **Free tier** — no payment needed. 1 request per 30 seconds, 256 KB/s.
- **Multiple regions** — North America, Europe, Ukraine, Tor exit.
- **vpn_fetch()** — make HTTP requests through VPN. Recommended tool.
- **Rate-limited tiers** — upgrade for more bandwidth and requests.
- **Machine fingerprint** — one account per device, prevents abuse.

## Tiers

| Tier | Price | Requests | Bandwidth |
|------|-------|----------|-----------|
| Free | 0 | 1 / 30s | 256 KB/s |
| Basic | 1 USDT/mo | 30 / min | 500 KB/s |
| Pro | 5 USDT/mo | 120 / min | 2 MB/s |

Payment via USDT on TON network. Upgrade by calling `vpn_activate()` and following the payment instructions.

## MCP Tools

| Tool | Description |
|------|-------------|
| `vpn_activate()` | Activate account. Free tier is instant. |
| `vpn_connect(node?)` | Connect to VPN exit node. |
| `vpn_disconnect()` | Disconnect. |
| `vpn_switch(node)` | Switch exit node. |
| `vpn_status()` | Account status, tier, quota. |
| `vpn_nodes()` | List available exit nodes. |
| `vpn_fetch(url, method?, headers?, body?)` | HTTP request through VPN. |
| `vpn_setup()` | Download VPN binary. Auto on first connect. |

## Configuration per tool

**Claude Code** — `.mcp.json` or `~/.claude/mcp.json`

**Cursor** — `.cursor/mcp.json` or `~/.cursor/mcp.json`

**Windsurf** — `~/.codeium/windsurf/mcp_config.json`

**OpenCode** — `opencode.json` or `~/.config/opencode/opencode.json`

**Continue** — `.continue/mcpServers/vpn.json`

**Hermes** — `~/.hermes/config.yaml` under `mcp_servers`

All use the same config:

```json
{
  "mcpServers": {
    "vpn": {
      "command": "vpn-mcp"
    }
  }
}
```

## Links

- Website: [vpn-mcp.net](https://vpn-mcp.net)
- Setup guide: [vpn-mcp.net/setup](https://vpn-mcp.net/setup)
- PyPI: [pypi.org/project/vpn-mcp](https://pypi.org/project/vpn-mcp/)

## License

Source-available. See [LICENSE](LICENSE) for details.
