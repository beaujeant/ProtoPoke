# ProtoPoke — AI Guidance File

Orientation for AI assistants: enough to navigate, extend, and review the
codebase without reading every file. Keep this file accurate and short — if
something here drifts from the code, fix it; don't pad it.

---

## What this project is

ProtoPoke is a **personal TCP / UDP / SOCKS5 proxy and protocol-analysis
tool** — Burp Suite for arbitrary binary protocols. It:

- Intercepts any TCP, UDP, or SOCKS5-proxied connection and lets an operator
  inspect, modify, or drop individual frames in real time.
- Each forwarder picks a transport via `config.forwarder_type` (`tcp` /
  `udp` / `socks5`). TCP/SOCKS5 share the stream relay; UDP uses per-client
  -tuple flows; SOCKS5 discovers the upstream target from the handshake.
- Keeps the surviving side open when one peer disconnects (half-open
  `ONLY_SERVER` / `ONLY_CLIENT` sessions) so the operator can keep driving it
  from Forge. Controlled by `keep_upstream_on_client_disconnect` /
  `keep_client_on_server_disconnect` (both default `True`).
- Decodes binary frames using a YAML/JSON protocol definition.
- Replays (Forge) captured sessions, optionally editing fields, and fuzzes.
- Exposes all proxy operations as MCP tools for AI-driven testing.
- Provides a full terminal UI (Textual) and a Python API.

---

## Working in this repo (conventions)

- **No backward compatibility.** This is a personal tool with no external
  users — just change the code. Don't add compat shims, deprecation paths,
  legacy fallbacks, or keep dead code "just in case". Delete what's unused.
- **Docs are part of the deliverable.** When a change alters something a
  user, operator, or AI client can observe, update the relevant page under
  `docs/` in the *same* change (see the doc map at the bottom). Keep docs
  concise — document the behaviour, don't pad. If you knowingly skip a needed
  doc update, say so in the commit/PR rather than letting docs drift.
- Match the existing style: dataclasses, async-only I/O, dependencies passed
  as constructor args (no globals, no DI framework).

---

## Running things

```bash
pip install -e ".[dev,mcp]"      # dev install (pytest + MCP deps)
pytest                           # all tests
pytest tests/test_framing.py     # one file
pytest -k test_length_prefix     # one test

protopoke                        # launch the TUI
protopoke --mcp                  # TUI + embedded MCP server on 127.0.0.1:7878
protopoke --mcp --mcp-host 127.0.0.1 --mcp-port 7878
```

The MCP server runs inside the UI process and shares the same `ProtoPokeAPI`
state, so a client on `http://127.0.0.1:7878/mcp` sees every session, rule,
and frame the UI sees, and vice versa. It can also be toggled at runtime from
the Config tab.

Tests use `pytest-asyncio` with `asyncio_mode = "auto"` — `async def test_*`
functions run automatically, no `@pytest.mark.asyncio` needed.

---

## Package layout

```
protopoke/
├── models.py           Core dataclasses: Frame, SessionInfo, TamperedUnit,
│                       ParsedMessage, ParsedField, Direction, SessionState
├── config.py           ForwarderConfig + ForwarderType enum
├── api.py              ProtoPokeAPI — the single public façade (start, stop,
│                       tamper, forge, fuzz, rules, events, …)
│
├── core/
│   ├── proxy.py        ProxyEngine — one per forwarder; start() dispatches on
│   │                   forwarder_type to the TCP / UDP / SOCKS5 listener
│   ├── relay.py        BidirectionalRelay + DirectionalRelay — TCP/SOCKS5 data
│   │                   path, incl. half-open (keep-alive) handling
│   ├── session.py      Session, SessionRegistry — in-memory session store
│   ├── socks5.py       SOCKS5 wire protocol (RFC 1928 + RFC 1929 user/pass)
│   └── udp_proxy.py    UdpFlow + datagram protocols — per-client-tuple UDP
│
├── framing/            Framer ABC + raw / delimiter / length_prefix / line.
│                       __init__.py: FRAMER_REGISTRY, create_framer(),
│                       load_framer_from_file()
│
├── protocol/
│   ├── base.py         ProtocolDecoder/Encoder ABCs, PassthroughDecoder
│   ├── definition/     schema.py (ProtocolDefinition/Message/Field),
│   │                   loader.py (load YAML/JSON), serializer.py (round-trips
│   │                   back to dict; powers read-only MCP definition tools)
│   ├── parser/         engine.py (DefinitionBased Decoder/Encoder),
│   │                   fields.py (per-type parse/encode), matcher.py
│   │                   (MAGIC/SEQUENCE/ALWAYS), expression.py (length/value)
│   └── display/        hexdump.py, tree.py (Wireshark-style), _color.py
│                       (ANSI/TTY colour support detection)
│
├── tamper/controller.py  TamperController ABC, PassthroughController,
│                         QueuedTamperController (the real intercept queue)
│
├── rules/              rule.py (ReplaceRule binary/regex/script, InterceptRule),
│                       engine.py (RulesEngine, InterceptFilter)
│
├── forge/              engine.py (ForgeEngine replay, PlaybookEngine,
│                       SendResult, ForgeResult), models.py (Playbook,
│                       PlaybookFrame, PlaybookRun, TrafficEntry),
│                       variables.py ({{VARIABLE}} resolution + transforms)
│
├── fuzzing/
│   ├── engine.py       FuzzerEngine — runs campaigns, detects anomalies
│   ├── models.py       FuzzCampaign, FuzzResult, CampaignStatus
│   └── mutators/       raw.py (BitFlip, ByteInsert, ByteDelete, KnownBad,
│                       Radamsa, Chain), field.py (FieldBoundary, FieldOverflow,
│                       NullByte, LengthMangle); base.py FrameMutator ABC
│
├── analysis.py         Pure protocol-agnostic helpers for the MCP reverse-
│                       engineering tools. Take a list[Frame], return dicts.
│                       Stats/bucketing, filtering, diffing, decoding,
│                       length/offset heuristics, structure discovery
│                       (constants, alignment, strings, TLV), and semantic
│                       detection (checksums, timestamps, compression/crypto,
│                       echo).
│
├── knowledge/          models.py (Finding, Note dataclasses — cross-session AI
│                       memory; carry author + locked), store.py (KnowledgeBase
│                       CRUD/filter/search). Persisted as findings.json +
│                       notes.json in the .pp archive.
│
├── tls/                ca.py (CertificateAuthority — per-session leaf certs),
│                       handler.py (TLSHandler — build ssl.SSLContext)
│
├── events/bus.py       EventBus (pub/sub). Events: SessionOpened/Closed/
│                       Updated, FrameCaptured, InterceptCompleted,
│                       UpstreamConnectionFailed
│
├── filters/frame_filter.py  FrameDisplayFilter — Traffic-tab display filters
│
├── project/manager.py  ProjectManager — save/load .pp ZIP (see below)
│
├── utils/script_loader.py  Loads user Python scripts (custom framers/rules)
│
├── mcp/
│   ├── server.py       build_mcp_server() — MCP tools wrapping ProtoPokeAPI.
│   │                   Protocol-definition surface is READ-ONLY
│   │                   (get_protocol_definition / _schema / get_protocol_info)
│   │                   — only the operator loads/saves a definition.
│   │                   Findings/notes CRUD enforce author/locked via
│   │                   _ai_can_mutate (AI may only mutate what it authored and
│   │                   the user hasn't locked in the TUI).
│   ├── guides/         Authoring guides (framers, protocol-definitions,
│   │                   replace-scripts) served as protopoke://guides[/<slug>]
│   │                   resources + list/get_authoring_guide tools
│   ├── recipes/        End-to-end workflow recipes served as
│   │                   protopoke://recipes[/<slug>] resources +
│   │                   list/get_workflow_recipe tools
│   ├── host.py         MCPHost — embedded server lifecycle (start/stop/rebind)
│   └── stdio_bridge.py protopoke-mcp console script — stdio↔HTTP forwarder for
│                       stdio-only clients (Claude/ChatGPT Desktop)
│
└── ui/
    ├── app.py          ProtoPoke(App) — Textual root; bridges asyncio EventBus
    │                   to the Textual message system
    ├── tabs/           config, traffic, tamper, forge, fuzzer, notes, logs
    ├── modals/         project, add_rule, frame_edit, forwarder_edit,
    │                   framer_edit, finding_edit, note_edit, playbook, …
    ├── widgets/        rule_table, parsed_view, segmented_control, help_button
    └── utils/frame_codec.py  bytes↔hex-string helpers
```

---

## Key data flow

```
Client TCP connection
        │
        ▼
ProxyEngine._handle_client()        [core/proxy.py]   (SOCKS5: _handle_socks5_client)
  creates Session, opens upstream, builds two Framers (one per direction)
        │
        ▼
BidirectionalRelay.run()            [core/relay.py]
  two concurrent tasks, one per direction:

  read() → Framer.feed() → [Frame, …]
                │
                ▼
          RulesEngine.apply()          replace rules (binary/regex/script)
                │
                ▼
          TamperController.process()   may block here if intercept is on
                │
                ▼
          writer.write()               forward (or drop) to other side
```

UDP (`core/udp_proxy.py`) bypasses the relay: one listening DatagramTransport
fans datagrams to a `UdpFlow` per `(client_host, client_port)`, each running
the same `RawFramer.feed → RulesEngine.apply → TamperController.process →
sendto` pipeline. UDP has no half-close; flows live until the forwarder stops
or `terminate_session()` is called.

Half-close (TCP/SOCKS5): by default the relay does NOT propagate EOF — it
stops that direction, transitions the session to `ONLY_SERVER`/`ONLY_CLIENT`,
and leaves the surviving side open (the `keep_*` config flags). The session
reaches `CLOSED` only when both sides are gone.

All data objects are plain dataclasses — immutable UUID IDs, JSON-serialisable
via `.to_dict()`.

---

## Core design principles

| Principle | How it manifests |
|-----------|-----------------|
| **No global state** | Components receive deps (config, event_bus, registry) as constructor args; ProtoPokeAPI wires them. |
| **Async-only, single loop** | Everything is `asyncio`, no threads. Registry/intercept queue need no locks. |
| **Immutable IDs** | Frame/Session/Rule IDs are UUID4 strings, set at creation. |
| **Layered isolation** | Relay knows nothing about framing; framer nothing about protocol; parser nothing about I/O. |
| **Pluggable via ABC** | Framers, decoders/encoders, mutators expose abstract interfaces. |
| **Explicit over magic** | No metaclasses, no plugin auto-discovery. Registration (e.g. `FRAMER_REGISTRY`) is explicit. |

### TUI event bridge
`ui/app.py` connects the asyncio `EventBus` to Textual: EventBus callbacks
`post_message(...)` a Textual `Message` subclass, which Textual dispatches to
`on_*` handlers that safely touch widgets on the Textual loop.

---

## Common extension points

- **New framer** — subclass `framing.base.Framer` (`feed`/`flush`/`reset`),
  then register in `framing/__init__.py`: `FRAMER_REGISTRY["x"] = MyFramer`.
- **Protocol decoder** — usually a YAML/JSON definition (see
  `examples/protocols/` and `docs/reference/protocol-definitions.md`):
  `api.set_protocol_file("p.yaml")`. For custom logic, implement the
  `ProtocolDecoder`/`ProtocolEncoder` ABCs and call `api.set_protocol(...)`.
- **New mutator** — subclass `fuzzing.mutators.base.FrameMutator`.
- **New field type / match strategy** — `protocol/parser/fields.py` /
  `matcher.py`.
- **New MCP tool** — `mcp/server.py`.

Protocol definition YAML: `name`, `endianness` (`big`/`little`), `messages[]`
each with a `match` (`magic`/`sequence`/`always`) and typed `fields[]`. Field
types: `uint8/16/32/64`, `int8/16/32/64`, `float32/64`, `bytes`, `string`,
`cstring`, `bitfield`, `array`, `tlv_sequence`. Full reference and examples in
`docs/reference/protocol-definitions.md`.

---

## Project file (.pp)

A ZIP archive with JSON members: `project.json`, `forwarders.json`,
`rules.json`, `forge.json`, `logs.json`, `filters.json`, `mcp.json`,
`findings.json`, `notes.json`. Loading is bounded (≤32 members, ≤100 MB each).
See `project/manager.py`.

---

## Tests

`tests/` has one `test_<area>.py` per subsystem (framing, parser, relay/proxy
integration, tamper, rules, forge, fuzzing, tls, socks5, udp, mcp_*, knowledge,
analysis, …) plus shared fixtures in `conftest.py`. Add tests beside the area
you change; `ls tests/` to find the right file.

---

## Frequently needed file locations

| Task | File |
|------|------|
| Change what ProtoPokeAPI exposes | `protopoke/api.py` |
| Frame capture / interception data path | `protopoke/core/relay.py` |
| TCP/UDP/SOCKS5 listener dispatch | `protopoke/core/proxy.py` |
| UDP flow handling | `protopoke/core/udp_proxy.py` |
| SOCKS5 handshake / wire protocol | `protopoke/core/socks5.py` |
| Add a forwarder config field | `protopoke/config.py` |
| Add a framer | `protopoke/framing/` |
| Add a protocol field type | `protopoke/protocol/parser/fields.py` |
| Add a match strategy | `protopoke/protocol/parser/matcher.py` |
| Add a mutator | `protopoke/fuzzing/mutators/` |
| Add an analytical helper | `protopoke/analysis.py` |
| Finding/Note fields or KB filters | `protopoke/knowledge/` |
| Add an MCP tool | `protopoke/mcp/server.py` |
| MCP author/locked enforcement | `protopoke/mcp/server.py` (`_ai_can_mutate`) |
| Definition → dict/YAML serialisation | `protopoke/protocol/definition/serializer.py` |
| TUI layout | `protopoke/ui/app.py`, `protopoke/ui/tabs/` |
| Project save/load format | `protopoke/project/manager.py` |
| TLS certificate behaviour | `protopoke/tls/ca.py`, `protopoke/tls/handler.py` |

---

## Doc map (update in the same change)

| Code change | Doc to update |
|-------------|---------------|
| MCP tools/resources/guides/recipes (`mcp/`) | `docs/mcp/tools.md` (+ `overview.md` for new surfaces; `analysis.md` / `knowledge.md` for those tool groups) |
| CLI flag / `--mcp*` option | `docs/mcp/configuration.md`, launch examples in `docs/mcp/overview.md` |
| New framer / mutator / field type / match strategy | matching page under `docs/reference/` |
| `ForwarderConfig` field / project key / API method | `docs/core/` (and the table above if navigation changes) |
| New TUI tab / modal / major widget | matching page under `docs/ui/` |
| New doc page | add it to `docs/docs.json` or it won't render |

When the project layout, data flow, or extension points change, update this
file too so the next AI session starts from accurate context.

---

## Intentionally not here

No ORM/database (dataclasses + JSON-in-ZIP), no config auto-discovery (always
passed explicitly), no DI framework (constructor args), no threading (single
asyncio loop), no HTTP API (control surface is `ProtoPokeAPI` + MCP).
