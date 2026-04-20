# MCP Configuration

The MCP server runs **embedded in the ProtoPoke UI process**, bound to the
same `ProtoPokeAPI` instance. AI clients connect to it over HTTP
(`streamable-http`) at `http://<host>:<port>/mcp` and share live state with
the operator: sessions, frames, rules, playbooks, the tamper queue, and
everything else visible in the TUI.

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mcp` | off | Enable the embedded MCP server on startup |
| `--mcp-host HOST` | `127.0.0.1` | Bind host for the MCP HTTP endpoint |
| `--mcp-port PORT` | `7878` | Bind port for the MCP HTTP endpoint |

The same settings can be toggled at runtime from the Config tab (Enabled
switch + Host / Port inputs). They are persisted per-project in the `.pp`
file (see `mcp.json`).

## Launch

```bash
pip install -e ".[mcp]"
protopoke --mcp                          # 127.0.0.1:7878
protopoke --mcp --mcp-port 7878          # explicit port
```

Once enabled, `http://127.0.0.1:7878/mcp` is the URL to register with an
MCP client.

## Claude Desktop

Add a `protopoke` entry to your Claude Desktop MCP configuration:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "protopoke": {
      "url": "http://127.0.0.1:7878/mcp"
    }
  }
}
```

Start the TUI first (`protopoke --mcp`), then restart Claude Desktop. A
hammer icon will appear in the chat input bar when the server is connected.

## Claude Code

```bash
claude mcp add --transport http protopoke http://127.0.0.1:7878/mcp
```

Or add it directly to `.mcp.json` / `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "protopoke": {
      "transport": "http",
      "url": "http://127.0.0.1:7878/mcp"
    }
  }
}
```

## Programmatic Usage

Build and embed the MCP server yourself (e.g. for custom hosting):

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig
from protopoke.mcp.host import MCPHost, MCPSettings

async def main():
    fwd = ForwarderConfig(
        name="Default",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
    )
    api = ProtoPokeAPI([fwd])
    await api.start()

    host = MCPHost(api, MCPSettings(enabled=True, host="127.0.0.1", port=7878))
    await host.start()

    try:
        await asyncio.Event().wait()  # run forever
    finally:
        await host.stop()
        await api.stop()

asyncio.run(main())
```

If you just need the raw `FastMCP` instance (for example to mount it under
another ASGI app), call `build_mcp_server(api)` directly:

```python
from protopoke.mcp.server import build_mcp_server

mcp = build_mcp_server(api, name="ProtoPoke")
# mcp is a FastMCP instance; call mcp.run_async(transport="streamable-http")
# or embed it via mcp.settings.host / mcp.settings.port.
```
