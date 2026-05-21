---
title: "MCP Server"
---

ProtoPoke exposes all proxy operations as [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) tools. Once connected, an AI assistant can fully control the proxy — inspect sessions, tamper and modify frames, forge/replay traffic, manage rules, run fuzzing campaigns, and more — all through natural language.

The server also returns **instructions** at `initialize` time — server-level guidance surfaced to the AI client describing what ProtoPoke is and how to use it well. The instructions tell the assistant to recover prior state on session start by calling `list_findings` (scoped by `protocol_name` or `forwarder_id`) and `list_notes` before re-running analysis, and to record what it learns as **findings** (concrete, scoped, evidence-backed protocol claims) versus **notes** (cross-cutting context).

## What the AI Can Do

| Capability | Example prompts |
|-----------|----------------|
| **Session inspection** | "List all sessions", "Show me the frames from session X", "Decode the frames and show field values" |
| **Protocol reversing** | "Cluster the frames by packet type", "Find the length field", "Decode bytes 2–5 as float32_le and show me when it changes", "Draft a `mv.yaml` protocol definition for these frames and hand me the YAML so I can load it" |
| **Live tamper** | "Enable tamper mode", "Show pending frames", "Forward the first one but change the username field to admin" |
| **Rules** | "Add an intercept rule for client→server frames starting with 0x01", "Clear all replace rules" |
| **Search** | "Find all frames containing the bytes FF FF 00" |
| **Replay** | "Replay session X", "Replay but change the password field to hunter2 in every LoginRequest" |
| **Forge** | "Send hex 01 02 03 to 10.0.0.1:9090", "Create a forge session and send a login packet" |
| **Protocol** | "Show me the active protocol definition", "Decode frame Y and explain each field" (loading and saving definitions is operator-only — the AI proposes YAML in chat) |
| **Knowledge** | "What did I learn last session about LoginRequest?", "Record that bytes 4–5 of LoginRequest are a CRC16 — confirmed by tampering tests on frames F1, F2", "Add a note that the server seems to echo the sequence number" |
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
  iteratively build a protocol definition that decodes it.  Includes
  the operator hand-off flow (the AI emits YAML in chat; the user
  loads it) and how to capture progress in the knowledge base.
- `protopoke://recipes/replay-with-mutation` — turn a captured session
  into a reusable playbook, parameterise it with variables, and run a
  fuzz campaign with mutators.
- `protopoke://recipes/intercept-and-rewrite` — choose between global
  replace rules, intercept rules, and script rules, and wire each one
  up end to end.

## Cross-session memory

Findings and free-form notes persist across AI sessions via the `.pp`
project file.  Use `add_finding` / `add_note` to record what you
learn; on session start, `list_findings` / `list_notes` recover the
previous session's reasoning.  See the
[Knowledge Base guide](/mcp/knowledge) for the schema and worked
example.

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

# Expose only the reverse-engineering tool subset (smaller per-turn token cost)
protopoke --mcp --mcp-profile analysis

# Or from the Config tab in the running TUI — toggle the "MCP" switch.
```

Connect an AI client to `http://127.0.0.1:7878/mcp`. See
[Configuration](/mcp/configuration) for all CLI flags, the `full` vs
`analysis` tool profiles, and integration guides.
