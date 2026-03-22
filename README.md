# ProtoPoke

A TCP proxy and protocol analysis tool — Burp Suite for arbitrary binary protocols.

Intercept any TCP connection, inspect and modify frames in real time, decode binary protocols with a YAML definition, replay sessions, fuzz with pluggable mutators, and let an AI assistant drive it all via MCP.

## Installation

**Python 3.11+ required.**

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke
pip install -e ".[dev]"
```

## Launch the TUI

```bash
protopoke
```

## MCP Server

Install with MCP support and launch:

```bash
pip install -e ".[mcp]"
protopoke-mcp --upstream-host 10.0.0.1 --upstream-port 9090
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp",
      "args": ["--upstream-host", "10.0.0.1", "--upstream-port", "9090"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add protopoke -- protopoke-mcp --upstream-host 10.0.0.1 --upstream-port 9090
```

## Quick Start

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ForwarderConfig, ProxyConfig

async def main():
    config = ProxyConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
    )
    api = ProxyAPI(forwarders=[ForwarderConfig(name="Default", enabled=True, config=config)])
    await api.start()

    while True:
        unit = await api.get_next_intercepted()
        print(unit.frame.raw_bytes.hex())
        api.forward(unit.id)

asyncio.run(main())
```

## Documentation

Full documentation is available at **[beaujeant.github.io/protopoke](https://beaujeant.github.io/protopoke/)**.

Covers the TUI, framing strategies, protocol definition DSL, tamper/intercept, forge/replay, fuzzing, TLS MITM, MCP tool reference, Python API, architecture, and more.

## Running Tests

```bash
pytest
```
