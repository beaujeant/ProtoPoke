# ProtoPoke

A TCP / UDP / SOCKS5 proxy and protocol analysis tool — Burp Suite for arbitrary binary protocols.

![Traffic](docs/assets/traffic.png)

Intercept any TCP, UDP, or SOCKS5-proxied connection, inspect and modify frames in real time, decode binary protocols with a YAML definition, replay sessions, fuzz with pluggable mutators, and let an AI assistant drive it all via MCP.

## Installation

**Python 3.11+ required.**

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke
```

### Using uv (recommended)

[uv](https://docs.astral.sh/uv/) creates the virtual environment and installs
everything in one step:

```bash
uv venv
uv pip install -e .
```

Then run commands with `uv run protopoke` (or activate the env with
`source .venv/bin/activate` and call `protopoke` directly).

### Using pip

```bash
pip install -e .
```

This installs everything needed to run the tool. Optional extras work the same
way with either installer:

```bash
uv pip install -e ".[mcp]"   # add MCP server support
uv pip install -e ".[dev]"   # add the test runner (for contributors)

pip install -e ".[mcp]"      # pip equivalent
pip install -e ".[dev]"
```

## Launch the TUI

```bash
protopoke
```

## MCP Server

The MCP server is **embedded in the TUI process** and bound to the same
`ProtoPokeAPI` instance that the UI uses, so an AI assistant sees and mutates
the exact same sessions, rules, and traffic that the operator sees on screen.
It is served over streamable-http on `http://<host>:<port>/mcp`.

Install with MCP support and launch the TUI with the server enabled:

```bash
uv pip install -e ".[mcp]"               # or: pip install -e ".[mcp]"
protopoke --mcp                          # 127.0.0.1:7878 by default
protopoke --mcp --mcp-port 7878          # custom port
```

### Tool profiles

`--mcp-profile` controls which tools the server exposes:

```bash
protopoke --mcp --mcp-profile full       # default — every tool
protopoke --mcp --mcp-profile analysis   # reverse-engineering subset only
```

- **`full`** (default) exposes the complete surface: forwarder lifecycle,
  replace/intercept rules, the tamper queue, playbooks, replay, fuzzing,
  variables, and TLS, plus all inspection and analysis tools.
- **`analysis`** drops the operational tools and keeps only the
  reverse-engineering subset (session/frame inspection, analysis helpers,
  the knowledge base, read-only protocol-definition tools, and the
  send/inject/forge probes) — handy for cutting the AI's token cost when you
  only want it to analyse traffic.

The profile can also be changed at runtime from the Config tab; changing it
restarts the embedded server.

### Claude Desktop

Claude Desktop can only launch **stdio** MCP servers from its config, but the
ProtoPoke server speaks streamable-http. Use the bundled `protopoke-mcp` stdio
bridge, which forwards stdio to the running TUI's HTTP endpoint.

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp"
    }
  }
}
```

The bridge connects to `http://127.0.0.1:7878/mcp` by default. If you moved the
server, point it at the new address with `--url` (or the `PROTOPOKE_MCP_URL`
environment variable):

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

Start the TUI with `protopoke --mcp` before launching Claude Desktop.

### Claude Code

Claude Code accepts an HTTP transport directly, so it connects to the server
URL without the bridge:

```bash
claude mcp add --transport http protopoke http://127.0.0.1:7878/mcp
```

Start the TUI with `protopoke --mcp` before connecting.

## Quick Start

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig

async def main():
    fwd = ForwarderConfig(
        name="Default",
        forwarder_type="tcp",      # "tcp" | "udp" | "socks5"
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
    )
    api = ProtoPokeAPI([fwd])
    await api.start()

    while True:
        unit = await api.get_next_intercepted()
        print(unit.frame.raw_bytes.hex())
        api.forward(unit.id)

asyncio.run(main())
```

## Documentation

Full documentation is available at **[protopoke.net](https://protopoke.net)**.

## Running Tests

```bash
pytest
```
