# ProtoPoke — AI Guidance File

This file helps AI assistants (Claude, Copilot, etc.) quickly understand the
codebase so they can navigate, extend, debug, and review it without having to
read every file from scratch.

---

## What this project is

ProtoPoke is a **personal TCP proxy and protocol-analysis tool** — Burp Suite
for arbitrary binary protocols. It:

- Intercepts any TCP connection and lets an operator inspect, modify, or drop
  individual frames in real-time (like Burp Suite's Repeater + Intercept).
- Decodes binary frames using a YAML/JSON protocol definition (named fields,
  typed, with size/offset metadata for Wireshark-style display).
- Replays (Forge) captured sessions against a server, optionally editing fields.
- Fuzzes sessions with a pluggable mutator pipeline.
- Exposes all proxy operations as MCP tools for AI-driven testing.
- Provides a full terminal UI (Textual) and a Python API.

---

## Running things

```bash
# Install (dev mode, includes pytest)
pip install -e ".[dev]"

# Run tests
pytest                          # all tests
pytest tests/test_framing.py    # one file
pytest -k test_length_prefix    # one test

# Launch the TUI
protopoke

# Launch the TUI with the embedded MCP server enabled on 127.0.0.1:7878
protopoke --mcp
protopoke --mcp --mcp-host 127.0.0.1 --mcp-port 7878
```

The MCP server runs inside the UI process and shares the same `ProtoPokeAPI`
state, so an AI client connected to `http://127.0.0.1:7878/mcp` sees every
session, rule, and frame visible in the UI and vice versa. The server can
also be toggled at runtime from the Config tab.

Tests use `pytest-asyncio` with `asyncio_mode = "auto"` (no `@pytest.mark.asyncio`
needed — all `async def test_*` functions run automatically).

---

## Top-level package layout

```
protopoke/
├── models.py           Core data classes: Frame, SessionInfo, TamperedUnit,
│                       ParsedMessage, ParsedField, Direction, SessionState, …
├── config.py           ForwarderConfig dataclass
├── api.py              ProtoPokeAPI — the single public façade (start, stop, tamper,
│                       forge, fuzz, rules, events, …)
│
├── core/
│   ├── proxy.py        ProxyEngine — asyncio server, one per forwarder
│   ├── relay.py        BidirectionalRelay + DirectionalRelay — the data path
│   └── session.py      Session, SessionRegistry — in-memory session store
│
├── framing/
│   ├── base.py         Framer ABC (feed/flush/reset/on_desync)
│   ├── raw.py          RawFramer — each read() == one frame (passthrough)
│   ├── delimiter.py    DelimiterFramer — split on byte sequence (\n, \r\n, …)
│   ├── length_prefix.py LengthPrefixFramer — 1/2/4/8-byte integer header
│   ├── line.py         LineFramer — convenience wrapper around delimiter
│   └── __init__.py     FRAMER_REGISTRY, create_framer(), load_framer_from_file()
│
├── protocol/
│   ├── base.py         ProtocolDecoder/Encoder ABCs, PassthroughDecoder
│   ├── definition/
│   │   ├── schema.py   ProtocolDefinition, MessageDefinition, FieldDefinition
│   │   └── loader.py   load_protocol_file() / load_protocol() (YAML/JSON)
│   ├── parser/
│   │   ├── engine.py   DefinitionBasedDecoder, DefinitionBasedEncoder
│   │   ├── fields.py   parse_field() / encode_field() per FieldType
│   │   ├── matcher.py  MessageMatcher — MAGIC / SEQUENCE / ALWAYS matching
│   │   └── expression.py ExpressionEvaluator — evaluate length/value expressions
│   └── display/
│       ├── hexdump.py  render_hexdump() — hex dump with per-field ANSI colour
│       └── tree.py     render_tree() — nested field tree (Wireshark style)
│
├── tamper/
│   └── controller.py   TamperController ABC, PassthroughController,
│                       QueuedTamperController (the real intercept queue)
│
├── rules/
│   ├── rule.py         ReplaceRule (binary/regex/script), InterceptRule
│   └── engine.py       RulesEngine, InterceptFilter
│
├── forge/
│   ├── engine.py       ForgeEngine (replay), PlaybookEngine (sequences),
│   │                   SendResult, ForgeResult
│   ├── models.py       Playbook, PlaybookFrame, PlaybookRun, TrafficEntry
│   └── variables.py    {{VARIABLE}} placeholder resolution + transforms
│
├── fuzzing/
│   ├── engine.py       FuzzerEngine — runs campaigns, detects anomalies
│   ├── models.py       FuzzCampaign, FuzzResult, CampaignStatus
│   └── mutators/
│       ├── base.py     FrameMutator ABC (single async mutate() method)
│       ├── raw.py      BitFlipMutator, ByteInsertMutator, ByteDeleteMutator,
│       │               KnownBadMutator, RadamsaMutator, ChainMutator
│       └── field.py    FieldBoundaryMutator, FieldOverflowMutator,
│                       NullByteMutator, LengthMangleMutator
│
├── tls/
│   ├── ca.py           CertificateAuthority — generate/sign per-session certs
│   └── handler.py      TLSHandler — build ssl.SSLContext for listen + upstream
│
├── events/
│   └── bus.py          EventBus (pub/sub), event types:
│                       SessionOpenedEvent, SessionClosedEvent,
│                       SessionUpdatedEvent, FrameCapturedEvent,
│                       InterceptCompletedEvent, UpstreamConnectionFailedEvent
│
├── project/
│   └── manager.py      ProjectManager — save/load .pp ZIP files
│                       (project.json, forwarders.json, rules.json, forge.json)
│
├── mcp/
│   ├── server.py       build_mcp_server() — 70 MCP tools wrapping ProtoPokeAPI
│   └── host.py         MCPHost — embedded MCP server lifecycle (start/stop/
│                       rebind), used by the Textual app to serve tools over
│                       streamable-http in the same process as the UI
│
└── ui/
    ├── app.py          ProtoPoke(App) — Textual root; event bridge between
    │                   asyncio EventBus and Textual message system
    ├── tabs/           config.py, traffic.py, tamper.py, forge.py,
    │                   fuzzer.py, logs.py
    ├── modals/         project.py, add_rule.py, frame_edit.py,
    │                   forwarder_edit.py, framer_edit.py, …
    ├── widgets/        rule_table.py, parsed_view.py
    └── utils/
        └── frame_codec.py  bytes↔hex-string helpers used across the UI
```

---

## Key data flow

```
Client TCP connection
        │
        ▼
ProxyEngine._handle_client()        [core/proxy.py]
  creates Session in SessionRegistry
  opens upstream TCP connection
  builds two Framer instances (one per direction)
        │
        ▼
BidirectionalRelay.run()            [core/relay.py]
  two concurrent asyncio Tasks, one per direction:

  read() → Framer.feed() → [Frame, Frame, …]
                │
                ▼
          RulesEngine.apply()       replace rules (binary/regex/script)
                │
                ▼
          TamperController.process()  may block here if intercept is on
                │
                ▼
          writer.write()            forward (or drop) to other side
```

All data objects (`Frame`, `SessionInfo`, `TamperedUnit`, `ParsedMessage`) are
plain dataclasses — immutable IDs, serialisable to JSON via `.to_dict()`.

---

## Core design principles

| Principle | How it manifests |
|-----------|-----------------|
| **No global state** | Every component receives its dependencies (config, event_bus, registry, …) as constructor args. ProtoPokeAPI wires them together. |
| **Async-only I/O** | Everything is `asyncio`. No threads. |
| **Single event loop** | All tasks share one loop. Session registry and intercept queue need no locks. |
| **Immutable IDs** | Frame/Session/Rule IDs are UUID4 strings, set at creation, never changed. |
| **Layered isolation** | Transport (relay) knows nothing about framing details. Framer knows nothing about protocol semantics. Parser knows nothing about network I/O. |
| **Pluggable via ABC** | Framers, decoders/encoders, and mutators all expose abstract interfaces. Swap implementations without touching callers. |
| **Explicit over magic** | No metaclasses, no auto-discovery of plugins. Registration (e.g. `FRAMER_REGISTRY`) is explicit. |

---

## How the TUI event bridge works

The asyncio `EventBus` publishes events from a background thread context.
Textual widgets must only be updated from the Textual main loop.

`ui/app.py` bridges this gap:

1. `_register_event_handlers()` subscribes async callbacks on the EventBus.
2. Each callback calls `self.post_message(...)` with a Textual `Message` subclass
   (`_SessionOpened`, `_SessionClosed`, `_SessionUpdated`, `_FrameCaptured`, …).
3. Textual dispatches those messages to `on__session_opened()`, etc. handlers,
   which safely call widget methods on the Textual thread.

---

## Common extension points

### Add a new framer

1. Subclass `protopoke.framing.base.Framer`.
2. Implement `feed(data) → list[Frame]`, `flush() → list[Frame]`, `reset()`.
3. Register in `protopoke/framing/__init__.py`:
   ```python
   FRAMER_REGISTRY["myframer"] = MyFramer
   ```

### Add a new mutator

1. Subclass `protopoke.fuzzing.mutators.base.FrameMutator`.
2. Implement `async mutate(frame, parsed_message) → bytes | None`.
   Return `None` to skip (e.g. frame is too short to mutate).
3. Pass an instance to `api.fuzz_session(..., mutators=[MyMutator()])`.

### Add a protocol decoder

Write a YAML definition file (see `examples/protocols/`) and call:
```python
api.set_protocol_file("my_protocol.yaml")
```
Or implement the `ProtocolDecoder` / `ProtocolEncoder` ABCs for fully custom
parsing logic and call `api.set_protocol(decoder, encoder)`.

---

## Protocol definition YAML structure

```yaml
name: MyProtocol
endianness: big          # big or little
messages:
  - name: LoginRequest
    match:
      type: magic        # magic | sequence | always
      offset: 0
      value: [0x01]      # bytes at offset must equal this
    fields:
      - name: msg_type
        type: uint8
      - name: username_len
        type: uint16
      - name: username
        type: bytes
        length: username_len   # expression referencing another field
      - name: flags
        type: bitfield
        size: 1
        bits:
          - name: is_admin
            bit: 0
```

Supported field types: `uint8`, `uint16`, `uint32`, `uint64`, `int8`, `int16`,
`int32`, `int64`, `float32`, `float64`, `bytes`, `string`, `cstring`,
`bitfield`, `array`, `tlv_sequence`.

Match strategies:
- `magic` — check fixed bytes at a given offset
- `sequence` — match by position in the stream (0-based index per direction)
- `always` — catch-all fallback (put last in the list)

---

## Project file format (.pp)

A `.pp` file is a ZIP archive containing:

```
project.json      — metadata (name, version)
forwarders.json   — list of ForwarderConfig dicts
rules.json        — {replace: [...], intercept: [...]}
forge.json        — list of Playbook dicts
traffic.json      — list of serialised Session dicts (optional)
logs.json         — log records (optional)
```

Version history:
- **v3**: single `config.json` (one forwarder only)
- **v4**: `forwarders.json` (multi-forwarder; current format)

The `ProjectManager.open()` method auto-migrates v3 files to v4 on load.

---

## Test layout

```
tests/
├── conftest.py                   shared fixtures (ForwarderConfig, free port, …)
├── test_proxy_integration.py     full end-to-end proxy flow
├── test_session.py               Session + SessionRegistry unit tests
├── test_framing.py               all four framers (raw, delimiter, length_prefix, line)
├── test_protocol_parser.py       DefinitionBasedDecoder + Encoder
├── test_protocol_definition.py   YAML/JSON schema loading
├── test_protocol_display.py      hexdump and tree renderers
├── test_tamper.py                QueuedTamperController
├── test_rules.py                 ReplaceRule + InterceptRule + engines
├── test_forge.py                 ForgeEngine replay
├── test_forge_models.py          Playbook / PlaybookFrame / PlaybookRun models
├── test_fuzzing.py               FuzzerEngine + mutators
├── test_fuzzing_integration.py   end-to-end fuzzing against a real server
├── test_events.py                EventBus pub/sub
├── test_config_serialization.py  ForwarderConfig round-trip
├── test_project_manager.py       save/open .pp ZIP files
├── test_models.py                Frame / SessionInfo / TamperedUnit / ParsedMessage
├── test_tls.py                   TLS MITM (CA generation, cert signing, handshake)
├── test_send_frame.py            api.send_frame() direct send
├── test_inject_to_server.py      api.inject_to_server() into live session
├── test_mcp_server.py            MCP tool coverage
├── test_to_dict_serialisation.py .to_dict() / .from_dict() round-trips
└── test_sequence.py              SEQUENCE match strategy
```

---

## Frequently needed file locations

| Task | File |
|------|------|
| Change what ProtoPokeAPI exposes | `protopoke/api.py` |
| Change frame capture / interception data path | `protopoke/core/relay.py` |
| Add a framer | `protopoke/framing/` |
| Add a protocol field type | `protopoke/protocol/parser/fields.py` |
| Add a match strategy | `protopoke/protocol/parser/matcher.py` |
| Add a mutator | `protopoke/fuzzing/mutators/` |
| Add an MCP tool | `protopoke/mcp/server.py` |
| Change the TUI layout | `protopoke/ui/app.py`, `protopoke/ui/tabs/` |
| Change project save/load format | `protopoke/project/manager.py` |
| Change TLS certificate behaviour | `protopoke/tls/ca.py`, `protopoke/tls/handler.py` |

---

## Things that are intentionally simple / not there

- **No ORM, no database** — models are dataclasses; project save/load is plain JSON in a ZIP archive.
- **No configuration file auto-discovery** — config is always passed explicitly.
- **No dependency injection framework** — dependencies are constructor arguments.
- **No threading** — single asyncio event loop throughout.
- **No HTTP API** — control surface is `ProtoPokeAPI` (Python) and MCP (AI tools).
  Adding an HTTP layer would wrap `ProtoPokeAPI` methods with no core changes.
