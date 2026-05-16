# ProtoPoke — AI Guidance File

This file helps AI assistants (Claude, Copilot, etc.) quickly understand the
codebase so they can navigate, extend, debug, and review it without having to
read every file from scratch.

---

## What this project is

ProtoPoke is a **personal TCP / UDP / SOCKS5 proxy and protocol-analysis
tool** — Burp Suite for arbitrary binary protocols. It:

- Intercepts any TCP, UDP, or SOCKS5-proxied connection and lets an operator
  inspect, modify, or drop individual frames in real-time (like Burp Suite's
  Repeater + Intercept).
- Each forwarder picks a transport via `config.forwarder_type` (`tcp` /
  `udp` / `socks5`). TCP/SOCKS5 share the stream relay; UDP uses per-client
  -tuple flows; SOCKS5 discovers the upstream target from the handshake.
- Keeps the surviving side of a connection open when one peer disconnects
  (half-open sessions: `ONLY_SERVER` / `ONLY_CLIENT`) so the operator can
  keep driving it from Forge. Controlled by the
  `keep_upstream_on_client_disconnect` / `keep_client_on_server_disconnect`
  config flags (both default `True`; set `False` for legacy TCP half-close).
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
│   ├── proxy.py        ProxyEngine — one per forwarder; start() dispatches on
│   │                   forwarder_type to the TCP / UDP / SOCKS5 listener
│   ├── relay.py        BidirectionalRelay + DirectionalRelay — the TCP/SOCKS5
│   │                   data path, incl. half-open (keep-alive) handling
│   ├── session.py      Session, SessionRegistry — in-memory session store
│   ├── socks5.py       SOCKS5 wire protocol (RFC 1928 + RFC 1929 user/pass)
│   └── udp_proxy.py    UdpFlow + datagram protocols — per-client-tuple UDP
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
│   │   ├── loader.py   load_protocol_file() / load_protocol() (YAML/JSON)
│   │   └── serializer.py protocol_to_dict()/message_to_dict()/field_to_dict()
│   │                     — round-trips with the loader (powers MCP protocol
│   │                     definition editing tools and save_protocol_to_file)
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
├── analysis.py         Pure analytical helpers used by the MCP reverse-
│                       engineering tools. Protocol-agnostic; takes a list
│                       of Frame objects and returns plain dicts. Covers
│                       bucketing/stats (frame_stats, entropy_map,
│                       cluster_frames), filtering (select_frames),
│                       diffing (compare_two_frames, diff_bucket),
│                       decoding (decode_field), heuristics
│                       (analyze_byte_ranges, find_length_field_candidates,
│                       offset_correlations), structure discovery
│                       (find_constant_byte_sequences, align_frames,
│                       extract_strings, detect_tlv), and semantic
│                       field detection (detect_checksums_crcs,
│                       detect_timestamps, detect_compression_encryption,
│                       echo_detection).
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
├── filters/
│   └── frame_filter.py FrameDisplayFilter — Traffic-tab display filters
│
├── project/
│   └── manager.py      ProjectManager — save/load .pp ZIP files (project.json,
│                       forwarders.json, rules.json, forge.json, logs.json,
│                       filters.json, mcp.json)
│
├── utils/
│   └── script_loader.py  Loads user Python scripts (custom framers, script rules)
│
├── mcp/
│   ├── server.py       build_mcp_server() — ~74 MCP tools wrapping ProtoPokeAPI
│   ├── host.py         MCPHost — embedded MCP server lifecycle (start/stop/
│   │                   rebind), used by the Textual app to serve tools over
│   │                   streamable-http in the same process as the UI
│   └── stdio_bridge.py protopoke-mcp console script — stdio↔HTTP forwarder
│                       so stdio-only clients (Claude Desktop, ChatGPT
│                       Desktop, …) can talk to the embedded HTTP server
│
└── ui/
    ├── app.py          ProtoPoke(App) — Textual root; event bridge between
    │                   asyncio EventBus and Textual message system
    ├── tabs/           config.py, traffic.py, tamper.py, forge.py,
    │                   fuzzer.py, logs.py
    ├── modals/         project.py, add_rule.py, frame_edit.py,
    │                   forwarder_edit.py, framer_edit.py, …
    ├── widgets/        rule_table.py, parsed_view.py, segmented_control.py,
    │                   help_button.py
    └── utils/
        └── frame_codec.py  bytes↔hex-string helpers used across the UI
```

---

## Key data flow

```
Client TCP connection
        │
        ▼
ProxyEngine._handle_client()        [core/proxy.py]   (SOCKS5: _handle_socks5_client)
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

UDP forwarders (`core/udp_proxy.py`) bypass the relay: a single listening
DatagramTransport fans datagrams out to a `UdpFlow` per `(client_host,
client_port)` tuple, and each datagram runs through the same
`RawFramer.feed → RulesEngine.apply → TamperController.process → sendto`
pipeline in its own task. UDP has no half-close — flows live until the
forwarder stops or `terminate_session()` is called.

Half-close handling (TCP/SOCKS5): when one side disconnects, the relay does
NOT propagate EOF to the other side by default — it stops that direction's
relay, transitions the session to `ONLY_SERVER` / `ONLY_CLIENT`, and leaves
the surviving side fully open (see the `keep_*` config flags). The session
reaches `CLOSED` only when both sides are gone.

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

The asyncio `EventBus` publishes events from relay / proxy tasks. Textual
widgets must only be updated from the Textual main loop.

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
project.json      — metadata (name, timestamps)
forwarders.json   — list of ForwarderConfig dicts
rules.json        — {replace: [...], intercept: [...]}
forge.json        — list of Playbook dicts
logs.json         — captured sessions + frames (the Traffic tab content)
filters.json      — frame display filters
mcp.json          — embedded MCP server settings (enabled, host, port)
```

ZIP loading is bounded (max 32 members, 100 MB per member).

---

## Test layout

```
tests/
├── conftest.py                     shared fixtures (ForwarderConfig, free port, …)
├── test_proxy_integration.py       full end-to-end proxy flow
├── test_session.py                 Session + SessionRegistry unit tests
├── test_framing.py                 built-in framers (raw, delimiter, length_prefix, line)
├── test_protocol_parser.py         DefinitionBasedDecoder + Encoder
├── test_protocol_definition.py     YAML/JSON schema loading
├── test_protocol_display.py        hexdump and tree renderers
├── test_tamper.py                  QueuedTamperController
├── test_rules.py                   ReplaceRule + InterceptRule + engines
├── test_forge.py                   ForgeEngine replay
├── test_forge_models.py            Playbook / PlaybookFrame / PlaybookRun models
├── test_playbook_custom.py         Playbook custom-transport behaviour
├── test_fuzzing.py                 FuzzerEngine + mutators
├── test_fuzzing_integration.py     end-to-end fuzzing against a real server
├── test_events.py                  EventBus pub/sub
├── test_config_serialization.py    ForwarderConfig round-trip
├── test_update_forwarder_config.py hot-swap forwarder name/framer/protocol
├── test_project_manager.py         save/open .pp ZIP files
├── test_models.py                  Frame / SessionInfo / TamperedUnit / ParsedMessage
├── test_tls.py                     TLS MITM (CA generation, cert signing, handshake)
├── test_socks5_handshake.py        SOCKS5 wire-protocol negotiation
├── test_socks5_proxy.py            end-to-end SOCKS5 forwarder
├── test_udp_proxy.py               end-to-end UDP forwarder
├── test_udp_forge.py               Forge/replay over UDP
├── test_udp_session_reuse.py       UDP per-tuple flow reuse
├── test_send_frame.py              api.send_frame() direct send
├── test_inject_to_server.py        api.inject_to_server() into live session
├── test_inject_to_client.py        api.inject_to_client() into live session
├── test_mcp_server.py              MCP tool coverage
├── test_mcp_host.py                MCPHost lifecycle
├── test_mcp_analysis_tools.py      MCP analysis + protocol-definition editing tools
├── test_analysis.py                protopoke/analysis.py helpers (pure unit tests)
├── test_segmented_control.py       SegmentedControl widget
└── test_to_dict_serialisation.py   .to_dict() / .from_dict() round-trips
```

---

## Frequently needed file locations

| Task | File |
|------|------|
| Change what ProtoPokeAPI exposes | `protopoke/api.py` |
| Change frame capture / interception data path | `protopoke/core/relay.py` |
| Change TCP/UDP/SOCKS5 listener dispatch | `protopoke/core/proxy.py` |
| Change UDP flow handling | `protopoke/core/udp_proxy.py` |
| Change SOCKS5 handshake / wire protocol | `protopoke/core/socks5.py` |
| Add a forwarder config field | `protopoke/config.py` |
| Add a framer | `protopoke/framing/` |
| Add a protocol field type | `protopoke/protocol/parser/fields.py` |
| Add a match strategy | `protopoke/protocol/parser/matcher.py` |
| Add a mutator | `protopoke/fuzzing/mutators/` |
| Add an analytical helper (stats / diff / heuristic) | `protopoke/analysis.py` |
| Add an MCP tool | `protopoke/mcp/server.py` |
| Change how a ProtocolDefinition serialises back to dict/YAML | `protopoke/protocol/definition/serializer.py` |
| Change the TUI layout | `protopoke/ui/app.py`, `protopoke/ui/tabs/` |
| Change project save/load format | `protopoke/project/manager.py` |
| Change TLS certificate behaviour | `protopoke/tls/ca.py`, `protopoke/tls/handler.py` |

---

## Keeping the documentation in sync

The Mintlify docs under `docs/` are part of the deliverable — treat them
like code. Whenever a code change alters something a user, operator, or
AI client can observe, update the relevant doc page in the **same**
change. In particular:

- **New / renamed / removed MCP tools or resources** (`protopoke/mcp/`)
  → update `docs/mcp/tools.md` and, if the change introduces a new
  surface, also `docs/mcp/overview.md`. Recipes and authoring guides
  also need to be listed there.
- **New CLI flag or `--mcp*` option** → update `docs/mcp/configuration.md`
  and any launch examples in `docs/mcp/overview.md`.
- **New framer / mutator / field type / match strategy** → update the
  matching page under `docs/reference/` and, if behaviour is exposed to
  the AI, the relevant MCP doc section.
- **New `ForwarderConfig` field, project-file key, or `ProtoPokeAPI`
  method** → update `docs/core/` and (if relevant) this file's
  "Frequently needed file locations" table.
- **New TUI tab, modal, or significant widget** → update the matching
  page under `docs/ui/`.
- **New navigation page** → add it to `docs/docs.json`, otherwise it
  will not appear in the rendered site.

If a code change requires a doc change but you do not make it, call it
out explicitly in the PR / commit message rather than letting the docs
drift silently. The same applies to this `CLAUDE.md` file — when the
project layout, data flow, or extension points change, update the
relevant section here so future AI sessions start from accurate
context.

## Things that are intentionally simple / not there

- **No ORM, no database** — models are dataclasses; project save/load is plain JSON in a ZIP archive.
- **No configuration file auto-discovery** — config is always passed explicitly.
- **No dependency injection framework** — dependencies are constructor arguments.
- **No threading** — single asyncio event loop throughout.
- **No HTTP API** — control surface is `ProtoPokeAPI` (Python) and MCP (AI tools).
  Adding an HTTP layer would wrap `ProtoPokeAPI` methods with no core changes.
