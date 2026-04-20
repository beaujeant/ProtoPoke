# MCP Server

ProtoPoke exposes all proxy operations as [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) tools. Once connected, an AI assistant can fully control the proxy — inspect sessions, tamper and modify frames, forge/replay traffic, manage rules, run fuzzing campaigns, and more — all through natural language.

## What the AI Can Do

| Capability | Example prompts |
|-----------|----------------|
| **Session inspection** | "List all sessions", "Show me the frames from session X", "Decode the frames and show field values" |
| **Live tamper** | "Enable tamper mode", "Show pending frames", "Forward the first one but change the username field to admin" |
| **Rules** | "Add an intercept rule for client→server frames starting with 0x01", "Clear all replace rules" |
| **Search** | "Find all frames containing the bytes FF FF 00" |
| **Replay** | "Replay session X", "Replay but change the password field to hunter2 in every LoginRequest" |
| **Forge** | "Send hex 01 02 03 to 10.0.0.1:9090", "Create a forge session and send a login packet" |
| **Protocol** | "Load the protocol definition from myproto.yaml", "Decode frame Y and explain each field" |
| **Fuzzing** | "Start a fuzzing campaign with bit_flip and known_bad mutators", "Show results with anomalies only" |
| **TLS** | "Give me the CA certificate" |
| **Config** | "What port is the proxy listening on?", "Enable TLS on the upstream side" |

## Installation

```bash
pip install "protopoke[mcp]"
```

Or install everything:

```bash
pip install "protopoke[all]"
```

## Launching

The MCP server runs **embedded inside the ProtoPoke TUI**, bound to the same
`ProtoPokeAPI` instance the UI uses. It is served over **streamable-http**
at `http://<host>:<port>/mcp`, so the AI client sees the same live state as
the operator.

```bash
# Enable on startup (default 127.0.0.1:7878)
protopoke --mcp

# Or from the Config tab in the running TUI — toggle the "MCP" switch.
```

Connect an AI client to `http://127.0.0.1:7878/mcp`. See
[Configuration](configuration.md) for all CLI flags and integration guides.
