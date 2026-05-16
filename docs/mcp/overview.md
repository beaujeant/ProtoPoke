---
title: "MCP Server"
---

ProtoPoke exposes all proxy operations as [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) tools. Once connected, an AI assistant can fully control the proxy — inspect sessions, tamper and modify frames, forge/replay traffic, manage rules, run fuzzing campaigns, and more — all through natural language.

## What the AI Can Do

| Capability | Example prompts |
|-----------|----------------|
| **Session inspection** | "List all sessions", "Show me the frames from session X", "Decode the frames and show field values" |
| **Protocol reversing** | "Cluster the frames by packet type", "Find the length field", "Decode bytes 2–5 as float32_le and show me when it changes", "Add a `position` message to the active protocol with these fields and save it as `mv.yaml`" |
| **Live tamper** | "Enable tamper mode", "Show pending frames", "Forward the first one but change the username field to admin" |
| **Rules** | "Add an intercept rule for client→server frames starting with 0x01", "Clear all replace rules" |
| **Search** | "Find all frames containing the bytes FF FF 00" |
| **Replay** | "Replay session X", "Replay but change the password field to hunter2 in every LoginRequest" |
| **Forge** | "Send hex 01 02 03 to 10.0.0.1:9090", "Create a forge session and send a login packet" |
| **Protocol** | "Load the protocol definition from myproto.yaml", "Decode frame Y and explain each field" |
| **Fuzzing** | "Start a fuzzing campaign with bit_flip and known_bad mutators", "Show results with anomalies only" |
| **Forwarders** | "Start the game-server forwarder", "Switch the active framer to length-prefix with a 4-byte header", "Load the auth.yaml protocol on the login forwarder without restarting" |
| **TLS** | "Give me the CA certificate" |
| **Config** | "What port is the proxy listening on?", "Enable TLS on the upstream side" |
| **Authoring** | "Show me the framer authoring guide", "Write a script replace rule that XORs bytes 4–8 with a session variable and tell me how to load it" |

## Authoring Guides & Script Hand-off

The MCP server ships short markdown guides for each of ProtoPoke's
extension points so an assistant can produce a correct artefact in one
shot. They are available both as MCP resources (`protopoke://guides`,
`protopoke://guides/framers`, `protopoke://guides/protocol-definitions`,
`protopoke://guides/replace-scripts`) and as tools (`list_authoring_guides`
/ `get_authoring_guide`).

Script replace rules execute arbitrary Python in the proxy process, so
ProtoPoke deliberately does **not** expose any MCP tool that persists a
script file or registers a script-type rule — the operator must accept
the code. After generating a script, call `get_script_load_instructions`
to quote the exact click-path back to the user.

## Workflow Recipes

Where authoring guides describe **one** extension point, workflow
recipes describe **end-to-end tasks** that chain several MCP tools
together. They are useful for an assistant that is about to drive a
multi-step job and wants a tool-by-tool walkthrough.

Available recipes:

- `protopoke://recipes/reverse-engineer-unknown-protocol` — capture,
  cluster, and analyse traffic from an unknown binary protocol, then
  iteratively build a protocol definition that decodes it.
- `protopoke://recipes/replay-with-mutation` — turn a captured session
  into a reusable playbook, parameterise it with variables, and run a
  fuzz campaign with mutators.
- `protopoke://recipes/intercept-and-rewrite` — choose between global
  replace rules, intercept rules, and script rules, and wire each one
  up end to end.

An index of every recipe is served at `protopoke://recipes`. Clients
without resource support can use the `list_workflow_recipes` /
`get_workflow_recipe` tool fallbacks.

## Tool Index (cheat-sheet)

A single curated markdown document listing every MCP tool grouped by
concern, with cross-references to the guides and recipes above. Useful
for client-side tool discovery and as a first read for a new assistant
session. Served as the `protopoke://tools` MCP resource.

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
[Configuration](/mcp/configuration) for all CLI flags and integration guides.
