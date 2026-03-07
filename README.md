# tcpproxy

A personal TCP interception and replay tool — think Burp Suite for arbitrary binary protocols.

Proxy any TCP connection, capture traffic in both directions, pause and inspect frames, modify or drop them live, and replay captured sessions against a server. Load a YAML protocol definition and frames are automatically decoded into named fields with a Wireshark-style hex + tree view, and you can edit individual fields by name during intercept or replay.

This is a personal security research tool. It prioritises **readability, extensibility, and hackability** over throughput.

---

## Features

- **Transparent TCP proxy** — listens locally, forwards to any upstream host/port
- **TLS/SSL MITM** — auto-generates a root CA and per-session certificates (Burp-style); clients trust the CA once, proxy decrypts all sessions transparently
- **Multi-session** — handles many concurrent connections on one listener
- **Bidirectional capture** — every frame logged with direction, timestamp, sequence number
- **Interception queue** — pause frames mid-stream, inspect, modify, forward, or drop
- **Three built-in framers** — raw (passthrough), delimiter (`\n`, `\r\n`, …), length-prefix (1/2/4/8 byte)
- **Replay engine** — re-send captured sessions with optional per-frame modifications, direction filter, and frame selector syntax
- **Protocol definition DSL** — describe any binary protocol in a YAML or JSON file; no code required
- **Protocol parser** — automatically decode frames into named, typed fields with offset and size metadata
- **Three match strategies** — identify packet types by magic bytes, by stream sequence position, or with a catch-all
- **Rich field types** — integers (u/int 8/16/32/64, float), raw bytes, strings (UTF-8/ASCII/UTF-16), bitfields, length-prefixed arrays, TLV sequences
- **Field-level intercept editing** — modify a single field by name, length fields auto-recomputed on encode
- **Field-level replay** — replay with per-message-type field edits, no manual frame ID tracking needed
- **Wireshark-style display** — hex dump with per-field ANSI colour highlights + nested field tree panel
- **Event bus** — subscribe async handlers to session open/close and frame events
- **Pluggable storage** — interface ready for SQLite or any backend

---

## Dependencies

### Runtime

| Package | Purpose |
|---|---|
| `cryptography >= 41` | TLS MITM: root CA generation, per-session certificate signing |
| `pyyaml` *(optional)* | Load protocol definitions from `.yaml` / `.yml` files. JSON files work without it. |

The proxy core (relay, framing, intercept, replay, protocol parser) uses only the standard library. `cryptography` is only imported when `tls_listen=True` or `tls_upstream=True`. `pyyaml` is only imported when loading a YAML definition file.

### Development / testing

| Package | Purpose |
|---|---|
| `pytest >= 7.4` | Test runner |
| `pytest-asyncio >= 0.23` | asyncio test support |
| `pytest-cov >= 4.1` | Coverage reports |

---

## Installation

### uv (recommended)

```bash
# Clone the repo
git clone https://github.com/beaujeant/tcpproxy.git
cd tcpproxy

# Create venv and install with dev extras
uv venv
uv pip install -e ".[dev]"

# Run tests
uv run pytest
```

### venv + pip

```bash
git clone https://github.com/beaujeant/tcpproxy.git
cd tcpproxy

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pytest
```

> **Python 3.11+ required.**

---

## start() vs serve_forever()

`ProxyAPI` has two ways to run:

| Method | Behaviour | When to use |
|---|---|---|
| `await api.start()` | Binds the port and returns immediately | When you need to do other work concurrently (intercept loop, test assertions, second server, …). You must call `await api.stop()` yourself. |
| `await api.serve_forever()` | Calls `start()` then blocks until the process is killed | Standalone scripts where the proxy is the only thing running. No need to call `stop()`. |

```python
# Standalone script — serve_forever() is simplest
async def main():
    api = ProxyAPI(config)
    await api.serve_forever()          # blocks here; Ctrl-C to exit

# Proxy + intercept loop — use start() so both can run concurrently
async def main():
    api = ProxyAPI(config)
    await api.start()
    try:
        while True:
            unit = await api.get_next_intercepted()
            api.forward(unit.id)
    finally:
        await api.stop()               # always clean up
```

---

## Quick Start

```python
import asyncio
from tcpproxy.api import ProxyAPI
from tcpproxy.config import ProxyConfig

async def main():
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
    )
    api = ProxyAPI(config)
    await api.serve_forever()   # standalone script: blocks until Ctrl-C

asyncio.run(main())
```

Connect anything to `127.0.0.1:8080` and traffic is transparently forwarded to `10.0.0.1:9090`.

---

## Examples

### 1 — Passive capture with frame printing

```python
import asyncio
from tcpproxy.api import ProxyAPI
from tcpproxy.config import ProxyConfig
from tcpproxy.events.bus import FrameCapturedEvent

async def main():
    config = ProxyConfig(listen_port=8080, upstream_host="10.0.0.1", upstream_port=9090)
    api = ProxyAPI(config)

    async def on_frame(event: FrameCapturedEvent):
        arrow = "→" if event.frame.direction.value == "client_to_server" else "←"
        print(f"[{event.session.id[:8]}] {arrow} {event.frame.raw_bytes!r}")

    api.on_frame_captured(on_frame)
    await api.serve_forever()   # standalone: blocks until Ctrl-C, no stop() needed

asyncio.run(main())
```

> See `examples/simple_proxy.py` for a more complete version.

---

### 2 — Intercept, inspect, and modify frames

Enable interception in the config, then process the queue:

```python
import asyncio
from tcpproxy.api import ProxyAPI
from tcpproxy.config import ProxyConfig

async def main():
    config = ProxyConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        intercept_enabled=True,          # pause frames for operator decision
    )
    api = ProxyAPI(config)
    await api.start()                    # start() returns immediately
    try:
        while True:
            unit = await api.get_next_intercepted()   # blocks until a frame arrives
            frame = unit.frame

            print(f"Intercepted [{frame.direction.value}]: {frame.raw_bytes!r}")

            # Choose one:
            api.forward(unit.id)                      # forward as-is
            # api.drop(unit.id)                       # discard
            # api.modify_and_forward(unit.id, b"new data") # replace bytes
    finally:
        await api.stop()                 # always clean up after start()

asyncio.run(main())
```

> See `examples/intercept_demo.py` for an interactive CLI version with hex editing.

---

### 3 — Toggle interception at runtime

```python
# Disable — all pending frames are immediately forwarded
api.intercept_enabled = False

# Re-enable
api.intercept_enabled = True

# Forward everything currently queued (without disabling)
api.forward_all()
```

---

### 4 — Replay a captured session

```python
# After a session has closed:
result = await api.replay_session(session_id)

print(f"Sent {result.total_bytes_sent()} bytes")
for frame in result.server_frames_received():
    print(frame.raw_bytes)
```

Replay to a different server, or with modified frames:

```python
# Replace one frame's bytes in the replay
result = await api.replay_session(
    session_id,
    server_host="staging.internal",
    server_port=9090,
    modified_frames={frame_id: b"modified payload"},
)
```

> See `examples/replay_demo.py` for a full interactive demo.

---

### 5 — Protocol-aware framing

By default every `read()` chunk becomes one frame (raw framer). For line-based protocols:

```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    framer_name="delimiter",
    framer_kwargs={"delimiter": b"\r\n"},   # one frame per CRLF-terminated line
)
```

For length-prefix binary protocols:

```python
config = ProxyConfig(
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 4, "byte_order": "big"},  # 4-byte big-endian header
)
```

To implement a custom framer for your protocol:

```python
from tcpproxy.framing.base import Framer
from tcpproxy.framing import FRAMER_REGISTRY

class MyProtocolFramer(Framer):
    def feed(self, data: bytes) -> list[Frame]:
        # accumulate bytes in self._buffer, return complete frames
        ...
    def flush(self) -> list[Frame]: ...
    def reset(self) -> None: ...

FRAMER_REGISTRY["myproto"] = MyProtocolFramer

config = ProxyConfig(framer_name="myproto", ...)
```

---

### 6 — Inspect captured sessions

```python
from tcpproxy.models import Direction

sessions = api.list_sessions()
for session in sessions:
    print(session)

# Get frames for one session
frames = api.get_frames(session.id, direction=Direction.CLIENT_TO_SERVER)
for frame in frames:
    print(f"seq={frame.sequence_number}  {frame.raw_bytes.hex()}")
```

---

### 7 — Event subscriptions

```python
from tcpproxy.events.bus import SessionOpenedEvent, SessionClosedEvent

async def on_open(event: SessionOpenedEvent):
    print(f"Session opened: {event.session.id}")

async def on_close(event: SessionClosedEvent):
    print(f"Session closed: {event.session.id}")

api.on_session_opened(on_open)
api.on_session_closed(on_close)
```

---

### 8 — Limit concurrent sessions

```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    max_sessions=10,    # reject connections beyond this limit
)
```

---

### 9 — TLS MITM (Burp-style)

On first run the proxy auto-generates a root CA at `~/.tcpproxy/ca.crt`. Install that file as a trusted root in your client (browser, OS, curl, etc.) once. Every subsequent session gets a fresh CA-signed leaf certificate transparently.

```python
config = ProxyConfig(
    listen_port=8443,
    upstream_host="api.example.com",
    upstream_port=443,
    tls_listen=True,         # present CA-signed cert to clients
    tls_upstream=True,       # connect to the real server over TLS
    # tls_upstream_verify=False,  # uncomment to accept self-signed server certs
)
api = ProxyAPI(config)
await api.start()

# Export the CA cert so the client can trust it
with open("tcpproxy-ca.crt", "wb") as f:
    f.write(api.ca.cert_pem)
print("Install tcpproxy-ca.crt as a trusted root, then connect to localhost:8443")
```

TLS-only client side (proxy connects to a plain upstream):

```python
config = ProxyConfig(
    listen_port=8443,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    tls_listen=True,         # clients connect over TLS
    tls_upstream=False,      # upstream is plain TCP (default)
)
```

Supply your own certificate instead of using the auto-CA (e.g. a wildcard cert your clients already trust):

```python
config = ProxyConfig(
    listen_port=8443,
    upstream_host="api.example.com",
    upstream_port=443,
    tls_listen=True,
    tls_cert_path="/path/to/wildcard.crt",
    tls_key_path="/path/to/wildcard.key",
    tls_upstream=True,
    tls_upstream_verify=False,
)
```

Use a custom CA location (e.g. a corporate CA that machines already trust):

```python
config = ProxyConfig(
    tls_listen=True,
    tls_upstream=True,
    ca_cert_path="/etc/corporate-ca/ca.crt",
    ca_key_path="/etc/corporate-ca/ca.key",
    upstream_host="internal.corp",
    upstream_port=443,
)
```

---

### 10 — Protocol definitions

Define your protocol in a YAML file. Point the proxy at it and every captured frame is automatically decoded into named fields.

#### YAML definition format

Three ways to identify packet types:

```yaml
protocol:
  name: "MyProtocol"
  endianness: big          # or little

  messages:

    # Magic bytes at a fixed offset
    - name: "LoginRequest"
      direction: client_to_server   # optional direction filter
      match:
        type: magic
        offset: 0
        value: "0x01"              # or [0x01, 0x02] for multi-byte magic
      fields:
        - { name: opcode,        type: uint8  }
        - { name: username_len,  type: uint16 }
        - { name: username,      type: string, length: "{username_len}", encoding: utf8 }
        - { name: password_len,  type: uint16 }
        - { name: password,      type: bytes,  length: "{password_len}", display: hex }

    # Stream sequence position (no magic bytes — first packet from server)
    - name: "ServerBanner"
      match:
        type: sequence
        direction: server_to_client
        index: 0          # 0-based: 0 = first packet in this direction
      fields:
        - { name: banner, type: string, length: -1, encoding: ascii }

    # TLV-structured payload
    - name: "DataPacket"
      match:
        type: magic
        offset: 0
        value: "0x10"
      fields:
        - { name: opcode,        type: uint8  }
        - { name: total_length,  type: uint32 }
        - name: attributes
          type: tlv_sequence
          length: "{total_length - 5}"
          tlv:
            type_size: 2
            length_size: 2
            tags:
              0x0001: { name: "ChannelID",   value_type: uint32 }
              0x0002: { name: "ChannelName", value_type: string }
              0x0003: { name: "Payload",     value_type: bytes,  display: hex }

    # Array of repeated sub-structures
    - name: "UserList"
      match:
        type: magic
        offset: 0
        value: "0x20"
      fields:
        - { name: opcode,      type: uint8  }
        - { name: user_count,  type: uint16 }
        - name: users
          type: array
          array:
            count: "{user_count}"
            item:
              - { name: user_id,  type: uint32 }
              - { name: name_len, type: uint8  }
              - { name: name,     type: string, length: "{name_len}" }
              - name: flags
                type: bitfield
                bits:
                  0: online
                  1: away
                  2: admin

    # Status codes with human-readable labels
    - name: "LoginResponse"
      direction: server_to_client
      match:
        type: magic
        offset: 0
        value: "0x02"
      fields:
        - { name: opcode,  type: uint8 }
        - name: status
          type: uint8
          enum:
            0x00: "Success"
            0x01: "Invalid credentials"
            0x02: "Account locked"
        - { name: token, type: bytes, length: 16, display: hex }

    # Catch-all — matches anything not identified above
    - name: "Unknown"
      match:
        type: always
      fields:
        - { name: raw, type: bytes, length: -1, display: hex }
```

A complete working example is at `examples/protocols/chat.proto.yaml`.

#### Field type reference

| Type | Size | Notes |
|---|---|---|
| `uint8` / `uint16` / `uint32` / `uint64` | 1 / 2 / 4 / 8 B | Unsigned integer |
| `int8` / `int16` / `int32` / `int64` | 1 / 2 / 4 / 8 B | Signed integer |
| `float32` / `float64` | 4 / 8 B | IEEE 754 |
| `bytes` | variable | Raw bytes; `length` required |
| `string` | variable | Decoded text; `length` or `null_terminated: true` |
| `bitfield` | variable | Integer with named per-bit children |
| `array` | variable | Repeated sub-structure; `array.count` required |
| `tlv_sequence` | variable | Stream of T-L-V triples; `tlv` config required |
| `padding` | variable | Skip N bytes (alignment / reserved) |

Field `length` sources:
- Fixed integer: `length: 4`
- Another field: `length: "{username_len}"`
- Expression: `length: "{total_length - 5}"`
- Rest of frame: `length: -1`
- Null-terminated string: `null_terminated: true`

#### Loading a definition

```python
# Via config — auto-loaded on start()
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    protocol_definition_path="myproto.yaml",  # .yaml, .yml, or .json
)
api = ProxyAPI(config)
await api.start()

# Or at runtime
api.set_protocol_file("myproto.yaml")

# Or from a dict (useful in tests / scripts)
api.set_protocol_dict({
    "name": "MyProto",
    "messages": [...],
})
```

#### Decoding frames

```python
# Decode one frame
msg = api.decode_frame(frame)
print(msg.message_type)   # e.g. "LoginRequest"
for field in msg.fields:
    print(f"  {field.name}: {field.display_value}  (offset={field.offset}, size={field.size})")

# Decode all frames in a session
messages = api.decode_session_frames(session_id)

# Access a field by name
msg.field_by_name("username").value    # Python value (str, int, bytes, …)
msg.as_dict()                          # {field_name: value, …}
```

---

### 11 — Protocol-aware interception

```python
# get_next_intercepted_parsed() returns both the raw unit and the decoded view
unit, msg = await api.get_next_intercepted_parsed()

print(msg.message_type)               # "LoginRequest"
print(msg.field_by_name("username").value)  # "admin"

# Forward after editing a single field — length fields are auto-recomputed
api.modify_field_and_forward(unit.id, {"username": "hacker"})

# Or fall back to raw bytes
api.modify_and_forward(unit.id, b"\x01\x00\x06hacker...")
```

> See `examples/protocol_intercept_demo.py` for a full interactive CLI with field editing, hex editing, and the Wireshark-style display.

---

### 12 — Protocol-aware replay

Replay with per-message-type field edits. The encoder decodes each frame, applies your edits, and re-encodes — no manual frame ID tracking needed:

```python
result = await api.replay_session_with_field_edits(
    session_id=session_id,
    field_edits={
        "LoginRequest": {
            "username": "admin2",
            "password": b"newpassword",   # password_len is auto-updated
        },
    },
)
```

Mix with the existing `modified_frames` raw-bytes override for frames you want to control at the byte level:

```python
result = await api.replay_session(
    session_id,
    frame_selector="1-5",                    # only the first five frames
    modified_frames={frame_id: b"..."},       # raw override for specific frames
)
```

> See `examples/protocol_replay_demo.py` for a full interactive demo.

---

### 13 — Wireshark-style display

```python
from tcpproxy.protocol.display import (
    render_hexdump,
    render_field_tree,
    render_frame_header,
    highlights_from_message,
)

msg = api.decode_frame(frame)

# One-line summary
print(render_frame_header(frame, msg))
# Frame #3  C→S  10:23:45.123  48 bytes  [ChatProtocol] LoginRequest

# Field detail panel with box-drawing chrome
print(render_field_tree(msg))
# ┌─ ChatProtocol / LoginRequest ─────────────────────────────────────┐
# │  opcode       [0x0000,  1B]   0x01                                │
# │  username_len [0x0001,  2B]   5                                   │
# │  username     [0x0003,  5B]   admin                               │
# │  password_len [0x0008,  2B]   6                                   │
# │  password     [0x000A,  6B]   73 65 63 72 65 74                   │
# └────────────────────────────────────────────────────────────────────┘

# Hex dump with per-field colour highlights
highlights = highlights_from_message(msg)
print(render_hexdump(frame.raw_bytes, highlights=highlights))
# Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F    ASCII
# 00000000  01 00 05 61 64 6D 69 6E  00 06 73 65 63 72 65 74    ...admin..secret
```

Colour highlights are auto-disabled when stdout is not a TTY, or set `NO_COLOR=1` to force plain output.

---

## Repository Layout

```
tcpproxy/
├── pyproject.toml
├── tcpproxy/
│   ├── models.py           # Core data: Frame, ParsedField, ParsedMessage, SessionInfo, InterceptedUnit
│   ├── config.py           # ProxyConfig dataclass (networking, TLS, framing, protocol)
│   ├── api.py              # ProxyAPI — the unified control facade
│   ├── core/
│   │   ├── proxy.py        # ProxyEngine: listen, connect upstream, wire relay + TLS
│   │   ├── relay.py        # DirectionalRelay + BidirectionalRelay
│   │   └── session.py      # Session + SessionRegistry
│   ├── tls/
│   │   ├── ca.py           # CertificateAuthority: generate, persist, issue leaf certs
│   │   └── handler.py      # TLSHandler: build SSLContext for listen + upstream sides
│   ├── framing/
│   │   ├── base.py         # Framer abstract base class
│   │   ├── raw.py          # Passthrough: each read() chunk = one frame
│   │   ├── delimiter.py    # Split on a fixed byte sequence
│   │   └── length_prefix.py # Fixed-size integer length header (1/2/4/8 bytes)
│   ├── protocol/
│   │   ├── base.py         # ProtocolDecoder / ProtocolEncoder ABCs + PassthroughDecoder
│   │   ├── definition/
│   │   │   ├── schema.py   # Dataclasses: ProtocolDefinition, MessageDefinition, FieldDefinition, …
│   │   │   └── loader.py   # Load + validate from YAML / JSON / dict
│   │   ├── parser/
│   │   │   ├── engine.py   # DefinitionBasedDecoder (session-aware) + DefinitionBasedEncoder
│   │   │   ├── fields.py   # Per-type parsers → ParsedField; encode_field() for re-assembly
│   │   │   ├── matcher.py  # MessageMatcher: magic / sequence / always match rules
│   │   │   └── expression.py # Safe AST-gated evaluator for "{length_field - 5}" strings
│   │   └── display/
│   │       ├── hexdump.py  # Wireshark-style hex+ASCII dump with ANSI field highlights
│   │       └── tree.py     # Box-drawing field detail panel with nested TLV/array children
│   ├── intercept/
│   │   └── controller.py   # PassthroughController + QueuedInterceptController
│   ├── replay/
│   │   └── engine.py       # ReplayEngine + ReplayResult (direction filter, frame selector)
│   ├── events/
│   │   └── bus.py          # EventBus (pub/sub, async handlers)
│   └── storage/
│       └── base.py         # StorageBackend ABC, NullStorage, MemoryStorage
├── tests/                  # 176 tests (unit + integration)
└── examples/
    ├── simple_proxy.py                 # Passthrough with frame printing
    ├── intercept_demo.py               # Interactive CLI intercept / hex edit
    ├── replay_demo.py                  # Capture and replay sessions
    ├── protocol_intercept_demo.py      # Protocol-aware intercept with field editing
    ├── protocol_replay_demo.py         # Protocol-aware replay with field edits
    └── protocols/
        └── chat.proto.yaml             # Full example: magic, sequence, TLV, array, bitfield
```

---

## Key Design Decisions and Tradeoffs

### `asyncio` as the concurrency model

TCP proxying is entirely I/O-bound. `asyncio` handles many concurrent sessions in one thread with no locking — the session registry and intercept queue are shared safely because everything runs on the same event loop.

The intercept "pause" is implemented with `asyncio.Future`. When a frame is intercepted, the relay task awaits the future. Only that one relay direction suspends; the event loop stays alive and continues handling all other sessions, new connections, and the API. With threads you would need a queue and a lock.

**Tradeoff:** CPU-bound work (e.g. heavy protocol decoding) would block the event loop. For this use case (personal research tool, not a high-throughput pipeline) that's acceptable. Add `asyncio.to_thread()` at the decoder layer if needed.

### Strict layer separation

The five layers (transport, framing, protocol, intercept, replay) are in separate modules and never import each other out of order. The relay does not know about protocols; the intercept controller does not know about network sockets; the replay engine does not know about live sessions.

**Tradeoff:** More files than a monolith. The payoff is that you can swap any layer (e.g. add a new framer, a new intercept backend, a SQLite storage layer) without touching unrelated code.

### TCP half-close on EOF

When one side of the connection closes, the relay sends a TCP FIN (`write_eof()`) to the other side rather than immediately calling `close()`. This lets the remote peer finish sending its in-flight response before the connection tears down — essential for request/response protocols over TCP.

**Tradeoff:** Slightly more complex cleanup logic. `BidirectionalRelay` owns all four stream objects and closes them after both relay tasks have finished.

### Framing separated from protocol decoding

A framer finds *message boundaries* in the byte stream. A protocol decoder interprets *message content*. These are independent: you can frame without decoding (capture with an unknown protocol), swap framers without changing decoders, and add decoders later without touching the relay.

**Tradeoff:** Two abstraction layers instead of one. For a known, simple protocol you could merge them, but doing so would prevent reuse and make the intercept UI harder to build.

### ParsedField carries offset + size + raw bytes

Every `ParsedField` knows exactly where it lives in the original frame (`offset`, `size`, `raw_bytes`). This serves three purposes simultaneously: the hex-dump renderer can highlight each field's byte range in a distinct colour; the encoder can re-assemble bytes field-by-field when the operator edits a value; and nested structures (TLV entries, array items) are expressed as `children` on a parent field, matching the Wireshark tree model exactly.

**Tradeoff:** Slightly heavier objects than storing only the decoded value. The overhead is negligible at the frame sizes a research tool handles.

### Encoder auto-recomputes length fields

When a variable-length field (e.g. `username`) is edited and re-encoded, the encoder walks the message definition looking for any other field whose `length` expression is `{username_len}` and recalculates that field's value from the encoded byte count. The operator edits `username`, not `username_len`. This mirrors what Burp's repeater does transparently.

**Tradeoff:** The heuristic (`length == "{field_name}"`) covers the common case of a simple scalar length field. Complex interdependencies (e.g. a length field covering multiple downstream fields) may still need a manual override.

### Safe expression evaluator

Length and count expressions (`"{total_length - 5}"`) are evaluated with Python's `eval()` on an AST that has been pre-validated to allow only arithmetic operators, name references, and a fixed whitelist of builtins (`min`, `max`, `abs`, `int`). Any other node type — attribute access, subscript, import, arbitrary call — raises `ValueError` before `eval()` runs.

Protocol definitions are authored by the tool operator themselves from local files they control, so this is defence-in-depth against typos and accidental complexity rather than a security sandbox.

### `is None` checks instead of `or` for optional parameters

`empty_registry or SessionRegistry()` silently created a second registry because `SessionRegistry.__len__` returns `0` when empty, making an empty instance falsy. All optional dependency injection uses explicit `if x is not None else default` guards.

**Tradeoff:** More verbose than `or`. The verbosity is worth it — the `or` bug caused frames to be captured in a registry that the API never queried, a failure mode that is silent and very hard to debug.

### In-memory frame storage by default

Frames are kept in `Session.frames` (a plain list) during the session. The `StorageBackend` interface exists for persistence but defaults to a no-op. This keeps the core simple and dependency-free.

**Tradeoff:** Unbounded memory for long sessions with high traffic. Mitigated by a future SQLite backend that flushes frames on `FrameCapturedEvent`.

### TLS MITM: certificate-per-session, not ssl= on a socket

Passing `ssl=SSLContext` to asyncio is enough for TLS *forwarding* (encrypted tunnel, contents opaque). For TLS *interception* the proxy must terminate TLS on both sides independently so the relay operates on plaintext bytes. That requires the proxy to present a certificate the client trusts. Two-stage design:

1. **`tcpproxy/tls/ca.py`** — `CertificateAuthority` generates an RSA-2048 root CA on first run and persists it at `~/.tcpproxy/ca.crt`. For each target hostname it issues a short-lived leaf cert (RSA-2048, correct SAN for DNS or IP, signed by the CA, cached in-memory).
2. **`tcpproxy/tls/handler.py`** — `TLSHandler` builds `ssl.SSLContext` objects from those certs and exposes `get_listen_ssl_context()` / `get_upstream_ssl_context()` which are passed directly to `asyncio.start_server()` and `asyncio.open_connection()`. The relay, framing, and intercept layers are untouched — they see plaintext `StreamReader`/`StreamWriter` regardless of whether TLS is in use.

The `cryptography` library is used specifically for cert generation because Python's built-in `ssl` module has no API for creating X.509 certificates programmatically.

**Tradeoff:** TLS does not support TCP half-close (`write_eof()` raises `NotImplementedError` on `SSLTransport`). The relay's `_send_eof_to_dest()` already guards with `can_write_eof()` before calling `write_eof()`, so the relay code is unchanged. For TLS sessions, the connection closes fully rather than half-closes when one side finishes sending.

---

## Roadmap

### Near term

- **SQLite persistence** — implement `SqliteStorageBackend` using `aiosqlite`. Subscribe to `FrameCapturedEvent` and write frames as they arrive. The `Frame` and `SessionInfo` dataclasses map directly to table rows with no schema redesign needed.

- **TLS MITM** ✅ *implemented* — auto-CA generation, per-session leaf certs, configurable upstream verify, manual cert override. See `tcpproxy/tls/` and [TLS MITM design decision](#tls-mitm-certificate-per-session-not-ssl-on-a-socket).

- **SNI-aware cert dispatch** — currently the proxy issues one leaf cert for `upstream_host` at startup. A full SNI callback (`ssl.SSLContext.set_servername_callback`) would let the proxy issue a correctly-named cert for each unique `server_name` presented during the TLS handshake, which matters when the same listener proxies multiple hostnames (e.g. a wildcard CONNECT proxy).

- **HTTP/REST control API** — wrap `ProxyAPI` in an `aiohttp` or `FastAPI` server to expose session listing, intercept queue, and replay over HTTP/WebSocket. This enables a browser-based UI without any changes to the proxy core.

### Protocol layer

- **Protocol definition DSL** ✅ *implemented* — define field layouts in YAML or JSON; the `DefinitionBasedDecoder` decodes frames automatically. Supports magic-byte, sequence, and always match rules; integers, bytes, strings, bitfields, arrays, TLV sequences; variable-length `{expression}` references; enum value labels; and display hints. See `tcpproxy/protocol/`.

- **Field-level intercept editing** ✅ *implemented* — `modify_field_and_forward()` re-encodes with a field name → value dict; length fields are auto-recomputed.

- **Field-level replay** ✅ *implemented* — `replay_session_with_field_edits()` applies per-message-type field edits across all matching frames in a replay.

- **Wireshark-style display** ✅ *implemented* — `render_hexdump()` with ANSI per-field highlights, `render_field_tree()` with nested children, `render_frame_header()` one-liner. See `tcpproxy/protocol/display/`.

- **Protobuf / Thrift / Kaitai** — compile existing IDL schemas into `ProtocolDecoder` implementations. The interface (`decode(frame) -> ParsedMessage`) is simple enough to wrap any existing parser.

- **Protocol decoder library** — implement `ProtocolDecoder` subclasses for common protocols (e.g. HTTP/1.1, Redis, DNS) as built-in options alongside the definition-based approach.

### UI

- **Terminal UI** — use `textual` or `prompt_toolkit` to build a Burp-like intercept queue view, session list, hex viewer, and in-place editor. All UI calls go through `ProxyAPI` — no direct access to internals.

### Advanced features

- **Fuzzing hooks** — add a `FrameMutator` interface that sits between the intercept controller and the relay. `ReplayEngine.replay_session(modified_frames=...)` already supports targeted replacement; a mutator layer can automate this for coverage-guided or random fuzzing.

- **Differential replay** — replay the same session against two servers and compare responses frame-by-frame. Useful for regression testing after a fix.

- **Timed replay** — honour original inter-frame delays from the captured session, or inject custom delays, to reproduce timing-sensitive bugs.

- **Per-session / per-direction intercept rules** — filter expressions (e.g. "only intercept frames matching this regex") to reduce noise when analysing high-volume protocols.

- **Plugin / dissector system** — load custom `Framer` or `ProtocolDecoder` subclasses from external Python modules at startup, without modifying the core package.
