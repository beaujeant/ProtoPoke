# ProtoPoke

A TCP / UDP / SOCKS5 proxy and protocol analysis tool — Burp Suite for arbitrary binary protocols.

Intercept any TCP, UDP, or SOCKS5-proxied connection, inspect and modify frames in real time, decode binary protocols with a YAML definition, replay sessions, fuzz with pluggable mutators, and let an AI assistant drive it all via MCP.

## Installation

**Python 3.11+ required.**

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke
pip install -e .
```

This installs everything needed to run the tool. Optional extras:

```bash
pip install -e ".[mcp]"   # add MCP server support
pip install -e ".[dev]"   # add the test runner (for contributors)
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
pip install -e ".[mcp]"
protopoke --mcp                          # 127.0.0.1:7878 by default
protopoke --mcp --mcp-port 7878          # custom port
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "protopoke": {
      "url": "http://127.0.0.1:7878/mcp"
    }
  }
}
```

### Claude Code

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

Full documentation is available at **[beaujeant.github.io/protopoke](https://beaujeant.github.io/protopoke/)**.

## Running Tests

```bash
pytest
```
