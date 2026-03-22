# MCP Configuration

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-host HOST` | `127.0.0.1` | Proxy bind address |
| `--listen-port PORT` | `8080` | Proxy listen port |
| `--upstream-host HOST` | `127.0.0.1` | Target host to forward to |
| `--upstream-port PORT` | `9090` | Target port to forward to |
| `--tamper` | off | Enable tamper mode on startup |
| `--tls-listen` | off | Terminate TLS on the client side (MITM) |
| `--tls-upstream` | off | Connect to upstream over TLS |
| `--framer NAME` | `raw` | Framer: `raw`, `delimiter`, or `length_prefix` |
| `--protocol PATH` | — | Path to a `.yaml`/`.json` protocol definition |
| `--config PATH` | — | Load a saved `ProxyConfig` JSON file (CLI flags override file values) |
| `--log-level LEVEL` | `WARNING` | Python logging level (logs go to stderr) |
| `--name NAME` | `ProtoPoke` | MCP server name shown to AI clients |

## Claude Desktop

Add a `protopoke` entry to your Claude Desktop MCP configuration:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

### Basic setup

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp",
      "args": [
        "--upstream-host", "10.0.0.1",
        "--upstream-port", "9090",
        "--listen-port", "8080"
      ]
    }
  }
}
```

### With TLS and protocol definition

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp",
      "args": [
        "--upstream-host", "api.example.com",
        "--upstream-port", "443",
        "--tls-listen",
        "--tls-upstream",
        "--protocol", "/path/to/myproto.yaml",
        "--tamper"
      ]
    }
  }
}
```

Restart Claude Desktop after editing. A hammer icon will appear in the chat input bar when the server is connected.

## Claude Code

Add ProtoPoke to your project's `.mcp.json` or `~/.claude/mcp.json`:

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

Or add it from the CLI:

```bash
claude mcp add protopoke -- protopoke-mcp --upstream-host 10.0.0.1 --upstream-port 9090
```

## OpenAI Agents SDK

OpenAI's [Agents SDK](https://github.com/openai/openai-agents-python) has native MCP support:

```bash
pip install openai-agents "protopoke[mcp]"
```

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    async with MCPServerStdio(
        name="ProtoPoke",
        params={
            "command": "protopoke-mcp",
            "args": [
                "--upstream-host", "10.0.0.1",
                "--upstream-port", "9090",
                "--listen-port", "8080",
                "--tamper",
            ],
        },
    ) as mcp_server:
        agent = Agent(
            name="ProxyAnalyst",
            instructions=(
                "You are a security researcher analysing binary protocol traffic "
                "captured by a ProtoPoke proxy. Use the available tools to inspect "
                "sessions, decode frames, intercept and modify packets, and replay "
                "traffic as needed."
            ),
            mcp_servers=[mcp_server],
        )

        result = await Runner.run(
            agent,
            "List all captured sessions and decode the frames in the first one."
        )
        print(result.final_output)

asyncio.run(main())
```

## Programmatic Usage

Build the MCP server directly in Python:

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ForwarderConfig, ProxyConfig
from protopoke.mcp.server import build_mcp_server

async def main():
    config = ProxyConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
    )
    api = ProxyAPI(forwarders=[ForwarderConfig(name="Default", enabled=True, config=config)])
    await api.start()

    mcp = build_mcp_server(api, name="ProtoPoke")
    await mcp.run_async()  # serves over stdio until disconnected

asyncio.run(main())
```
