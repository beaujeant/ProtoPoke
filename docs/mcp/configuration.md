---
title: "MCP Configuration"
---

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

## Why a stdio bridge?

The embedded MCP server only speaks `streamable-http` because it lives in
the long-running TUI process and shares one `ProtoPokeAPI` with the
operator. The standard Claude Desktop client (and many other AI agents)
only support launching **stdio** MCP servers from their config file —
they silently ignore `"url"` entries. To bridge the two, ProtoPoke ships
a tiny Python forwarder, `protopoke-mcp`, installed as a console script
alongside `protopoke`. It runs as a stdio MCP server, forwards every
message to/from the HTTP endpoint, and exits when the client closes.

```
┌──────────────────┐  stdio   ┌──────────────────┐  HTTP   ┌─────────────┐
│  AI client       │ ───────► │  protopoke-mcp   │ ──────► │  TUI proc   │
│  (Claude Desktop │ ◄─────── │  (stdio bridge)  │ ◄────── │  + MCP srv  │
│  / Cursor / ...) │          └──────────────────┘         └─────────────┘
└──────────────────┘
```

`protopoke-mcp` takes an optional `--url` (default
`http://127.0.0.1:7878/mcp`, also honoured via `$PROTOPOKE_MCP_URL`).
Always start the TUI first with `protopoke --mcp` so the bridge has
somewhere to connect to.

## Running from a local checkout without `pip install` (`uv`)

If you have ProtoPoke cloned locally and don't want to `pip install` it
into a system or user Python, [`uv`](https://docs.astral.sh/uv/) can run
both the TUI and the stdio bridge straight out of the checkout. `uv run`
materialises a `.venv` inside the project on first invocation, then reuses
it.

Run the TUI in a terminal (replace `/path/to/ProtoPoke` with your clone):

```bash
uv run --project /path/to/ProtoPoke --extra mcp protopoke --mcp
```

Point the AI client at `uv run` instead of `protopoke-mcp`:

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "uv",
      "args": [
        "run",
        "--project", "/path/to/ProtoPoke",
        "--extra", "mcp",
        "protopoke-mcp"
      ]
    }
  }
}
```

Use an absolute path for `--project` — AI clients launch the bridge from
their own working directory. If the client can't find `uv` on its `PATH`,
replace `"uv"` with the absolute path (`which uv` on macOS/Linux).

## Claude Desktop

Add a `protopoke` entry to your Claude Desktop MCP configuration:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp"
    }
  }
}
```

If you moved the MCP port, pass it through:

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp",
      "args": ["--url", "http://127.0.0.1:9000/mcp"]
    }
  }
}
```

Start the TUI first (`protopoke --mcp`), then restart Claude Desktop. A
hammer icon will appear in the chat input bar when the server is connected.

## Claude Code

Claude Code supports streamable-http directly, so the bridge is not needed:

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

## Other AI agents (Cursor, Windsurf, Cline, ChatGPT Desktop, …)

Any client that supports the standard stdio config format works with the
same snippet as Claude Desktop:

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp"
    }
  }
}
```

If the client supports streamable-http natively (e.g. Cursor), you can
skip the bridge and point it at `http://127.0.0.1:7878/mcp` directly.

## mcp-inspector

Both transports work:

```bash
# Via the bridge (stdio):
npx @modelcontextprotocol/inspector protopoke-mcp

# Direct HTTP:
npx @modelcontextprotocol/inspector --transport http http://127.0.0.1:7878/mcp
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
