---
title: "Architecture"
---

## Package Layout

```
protopoke/
├── models.py           Core data classes: Frame, SessionInfo, TamperedUnit,
│                       ParsedMessage, ParsedField, Direction, SessionState
├── config.py           ForwarderConfig dataclass
├── api.py              ProtoPokeAPI — the single public facade
│
├── core/
│   ├── proxy.py        ProxyEngine — one per forwarder; dispatches on
│   │                   forwarder_type to the TCP / UDP / SOCKS5 listener
│   ├── relay.py        BidirectionalRelay + DirectionalRelay — the TCP data
│   │                   path, incl. half-open (keep-alive) handling
│   ├── session.py      Session, SessionRegistry — in-memory session store
│   ├── socks5.py       SOCKS5 wire protocol (RFC 1928 + RFC 1929 auth)
│   └── udp_proxy.py    UdpFlow + datagram protocols — per-client-tuple UDP
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
├── filters/
│   └── frame_filter.py FrameDisplayFilter — Traffic-tab display filters
│
├── project/
│   └── manager.py      ProjectManager — save/load .pp ZIP files
│
├── utils/
│   └── script_loader.py  Loads user Python scripts (custom framers, rules)
│
├── mcp/
│   ├── server.py       build_mcp_server() — 70+ MCP tools
│   └── host.py         MCPHost — embedded server lifecycle (start/stop/
│                       rebind) running inside the Textual app process
│
└── ui/
    ├── app.py          ProtoPoke(App) — Textual root + event bridge
    ├── tabs/           config, traffic, tamper, forge, fuzzer, logs
    ├── modals/         project, add_rule, frame_edit, forwarder_edit, etc.
    ├── widgets/        rule_table, parsed_view, segmented_control, etc.
    └── utils/
        └── frame_codec.py  bytes ↔ hex-string helpers
```

Sessions and frames are kept entirely in memory for the lifetime of the
process; the only persistence is the `.pp` project file written by
`ProjectManager`. There is no database or storage-backend layer.

## Forwarder Types

`ProxyEngine.start()` dispatches on `config.forwarder_type`:

| Type | Listener | Session model |
|------|----------|---------------|
| `tcp` (default) | `asyncio.start_server` | One `BidirectionalRelay` per accepted connection |
| `socks5` | `asyncio.start_server` + RFC 1928/1929 handshake | Same as TCP, but the upstream target is discovered per-connection from the SOCKS `CONNECT` request; `socks_auth_username`/`socks_auth_password` enable username/password auth |
| `udp` | `loop.create_datagram_endpoint` | One `UdpFlow` per `(client_host, client_port)` tuple; no half-open / FIN — flows live until terminated or the forwarder stops |

UDP and SOCKS5 forwarders cannot enable `tls_listen` (DTLS is not supported,
and wrapping the SOCKS handshake in TLS is non-standard). UDP forwarders
always use the `raw` framer (one datagram = one frame).

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

The UDP path (`core/udp_proxy.py`) mirrors the same per-frame pipeline —
`RawFramer.feed` → `RulesEngine.apply` → `TamperController.process` →
`sendto` — but each datagram is processed in its own task rather than via a
long-lived relay loop.

## Design Principles

| Principle | How it manifests |
|-----------|-----------------|
| **No global state** | Every component receives dependencies as constructor args. ProtoPokeAPI wires them together. |
| **Async-only I/O** | Everything is `asyncio`. No threads. |
| **Single event loop** | All tasks share one loop. Session registry and intercept queue need no locks. |
| **Immutable IDs** | Frame/Session/Rule IDs are UUID4 strings, set at creation, never changed. |
| **Layered isolation** | Transport knows nothing about framing. Framer knows nothing about protocol semantics. Parser knows nothing about network I/O. |
| **Pluggable via ABC** | Framers, decoders/encoders, and mutators all expose abstract interfaces. |
| **Explicit over magic** | No metaclasses, no auto-discovery. Registration (e.g. `FRAMER_REGISTRY`) is explicit. |

## TUI Event Bridge

The asyncio `EventBus` publishes events from background tasks. Textual widgets must only be updated from the Textual main loop.

`ui/app.py` bridges this gap:

1. `_register_event_handlers()` subscribes async callbacks on the EventBus
2. Each callback calls `self.post_message(...)` with a Textual `Message` subclass
3. Textual dispatches those messages to `on_*` handlers, which safely update widgets
