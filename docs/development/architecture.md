# Architecture

## Package Layout

```
protopoke/
├── models.py           Core data classes: Frame, SessionInfo, TamperedUnit,
│                       ParsedMessage, ParsedField, Direction, SessionState
├── config.py           ForwarderConfig dataclass
├── api.py              ProtoPokeAPI — the single public facade
│
├── core/
│   ├── proxy.py        ProxyEngine — asyncio server, one per forwarder
│   ├── relay.py        BidirectionalRelay + DirectionalRelay — the data path
│   └── session.py      Session, SessionRegistry — in-memory session store
│
├── framing/
│   ├── base.py         Framer ABC
│   ├── raw.py          RawFramer — each read() = one frame
│   ├── delimiter.py    DelimiterFramer — split on byte sequence
│   ├── length_prefix.py LengthPrefixFramer — integer-header framing
│   ├── line.py         LineFramer — \r\n / \n splitter
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
│   │   └── expression.py  ExpressionEvaluator — length/value expressions
│   └── display/
│       ├── hexdump.py  render_hexdump() — hex dump with ANSI colour
│       └── tree.py     render_tree() — nested field tree
│
├── tamper/
│   └── controller.py   TamperController ABC, PassthroughController,
│                       QueuedTamperController
│
├── rules/
│   ├── rule.py         ReplaceRule, InterceptRule
│   └── engine.py       RulesEngine, InterceptFilter
│
├── forge/
│   ├── engine.py       ForgeEngine, PlaybookEngine, SendResult, ForgeResult
│   ├── models.py       Playbook, PlaybookFrame, PlaybookRun, TrafficEntry
│   └── variables.py    {{VARIABLE}} placeholder resolution
│
├── fuzzing/
│   ├── engine.py       FuzzerEngine — runs campaigns, detects anomalies
│   ├── models.py       FuzzCampaign, FuzzResult, CampaignStatus
│   └── mutators/
│       ├── base.py     FrameMutator ABC
│       ├── raw.py      BitFlip, ByteInsert, ByteDelete, KnownBad, Radamsa, Chain
│       └── field.py    FieldBoundary, FieldOverflow, NullByte, LengthMangle
│
├── tls/
│   ├── ca.py           CertificateAuthority — generate/sign certs
│   └── handler.py      TLSHandler — build ssl.SSLContext
│
├── events/
│   └── bus.py          EventBus (pub/sub) + event types
│
├── project/
│   └── manager.py      ProjectManager — save/load .pp ZIP files
│
├── storage/
│   ├── base.py         StorageBackend ABC, NullStorageBackend, MemoryStorageBackend
│   └── sqlite.py       SqliteStorageBackend
│
├── mcp/
│   ├── server.py       build_mcp_server() — 50+ MCP tools
│   └── runner.py       CLI entry point for protopoke-mcp
│
└── ui/
    ├── app.py          ProtoPoke(App) — Textual root + event bridge
    ├── tabs/           config, traffic, tamper, forge, fuzzer, logs
    ├── modals/         project, add_rule, frame_edit, forwarder_edit, etc.
    ├── widgets/        rule_table, parsed_view
    └── utils/
        └── frame_codec.py  bytes ↔ hex-string helpers
```

## Data Flow

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

## Design Principles

| Principle | How it manifests |
|-----------|-----------------|
| **No global state** | Every component receives dependencies as constructor args. ProtoPokeAPI wires them together. |
| **Async-only I/O** | Everything is `asyncio`. No threads except the SQLite executor bridge. |
| **Single event loop** | All tasks share one loop. Session registry and intercept queue need no locks. |
| **Immutable IDs** | Frame/Session/Rule IDs are UUID4 strings, set at creation, never changed. |
| **Layered isolation** | Transport knows nothing about framing. Framer knows nothing about protocol semantics. Parser knows nothing about network I/O. |
| **Pluggable via ABC** | Framers, decoders/encoders, mutators, storage backends all expose abstract interfaces. |
| **Explicit over magic** | No metaclasses, no auto-discovery. Registration (e.g. `FRAMER_REGISTRY`) is explicit. |

## TUI Event Bridge

The asyncio `EventBus` publishes events from background tasks. Textual widgets must only be updated from the Textual main loop.

`ui/app.py` bridges this gap:

1. `_register_event_handlers()` subscribes async callbacks on the EventBus
2. Each callback calls `self.post_message(...)` with a Textual `Message` subclass
3. Textual dispatches those messages to `on_*` handlers, which safely update widgets

## Extension Points

### Add a Framer

1. Subclass `protopoke.framing.base.Framer`
2. Implement `feed(data) → list[Frame]`, `flush() → list[Frame]`, `reset()`
3. Register in `protopoke/framing/__init__.py`:
   ```python
   FRAMER_REGISTRY["myframer"] = MyFramer
   ```

### Add a Mutator

1. Subclass `protopoke.fuzzing.mutators.base.FrameMutator`
2. Implement `async mutate(frame, parsed_message) → bytes | None`
3. Pass instances to `api.fuzz_session(..., mutators=[MyMutator()])`

### Add a Protocol Decoder

Write a YAML definition file and call `api.set_protocol_file("my_protocol.yaml")`, or implement `ProtocolDecoder`/`ProtocolEncoder` ABCs for fully custom logic.

### Add a Storage Backend

Subclass `protopoke.storage.base.StorageBackend`, implement the five async methods (`save_session`, `load_session`, `list_sessions`, `save_frame`, `load_frames`), and pass it to `ProtoPokeAPI(forwarders, storage=MyBackend())`.
