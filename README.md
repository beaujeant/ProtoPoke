# tcpproxy

A personal TCP interception and replay tool — think Burp Suite for arbitrary binary protocols.

Proxy any TCP connection, capture traffic in both directions, pause and inspect frames, modify or drop them live, and replay captured sessions against a server. Protocol-agnostic by design: plug in your own framer and decoder for any protocol.

This is a personal security research tool. It prioritises **readability, extensibility, and hackability** over throughput.

---

## Features

- **Transparent TCP proxy** — listens locally, forwards to any upstream host/port
- **Multi-session** — handles many concurrent connections on one listener
- **Bidirectional capture** — every frame logged with direction, timestamp, sequence number
- **Interception queue** — pause frames mid-stream, inspect, modify, forward, or drop
- **Three built-in framers** — raw (passthrough), delimiter (`\n`, `\r\n`, …), length-prefix (1/2/4/8 byte)
- **Replay engine** — re-send captured sessions with optional per-frame modifications
- **Event bus** — subscribe async handlers to session open/close and frame events
- **Pluggable storage** — interface ready for SQLite or any backend
- **No mandatory third-party dependencies** — stdlib only for the core

---

## Dependencies

### Runtime

Pure Python standard library. No third-party packages required.

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

### Natively (no venv)

```bash
git clone https://github.com/beaujeant/tcpproxy.git
cd tcpproxy

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

## Repository Layout

```
tcpproxy/
├── pyproject.toml
├── tcpproxy/
│   ├── models.py           # Core data: Frame, SessionInfo, InterceptedUnit, ParsedMessage
│   ├── config.py           # ProxyConfig dataclass
│   ├── api.py              # ProxyAPI — the unified control facade
│   ├── core/
│   │   ├── proxy.py        # ProxyEngine: listen, connect upstream, wire relay
│   │   ├── relay.py        # DirectionalRelay + BidirectionalRelay
│   │   └── session.py      # Session + SessionRegistry
│   ├── framing/
│   │   ├── base.py         # Framer abstract base class
│   │   ├── raw.py          # Passthrough: each read() chunk = one frame
│   │   ├── delimiter.py    # Split on a fixed byte sequence
│   │   └── length_prefix.py # Fixed-size integer length header (1/2/4/8 bytes)
│   ├── protocol/
│   │   └── base.py         # ProtocolDecoder / ProtocolEncoder ABCs
│   ├── intercept/
│   │   └── controller.py   # PassthroughController + QueuedInterceptController
│   ├── replay/
│   │   └── engine.py       # ReplayEngine + ReplayResult
│   ├── events/
│   │   └── bus.py          # EventBus (pub/sub, async handlers)
│   └── storage/
│       └── base.py         # StorageBackend ABC, NullStorage, MemoryStorage
├── tests/                  # 100 tests (unit + integration with real TCP)
└── examples/
    ├── simple_proxy.py     # Passthrough with frame printing
    ├── intercept_demo.py   # Interactive CLI intercept / hex edit
    └── replay_demo.py      # Capture and replay sessions
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

### `is None` checks instead of `or` for optional parameters

`empty_registry or SessionRegistry()` silently created a second registry because `SessionRegistry.__len__` returns `0` when empty, making an empty instance falsy. All optional dependency injection uses explicit `if x is not None else default` guards.

**Tradeoff:** More verbose than `or`. The verbosity is worth it — the `or` bug caused frames to be captured in a registry that the API never queried, a failure mode that is silent and very hard to debug.

### In-memory frame storage by default

Frames are kept in `Session.frames` (a plain list) during the session. The `StorageBackend` interface exists for persistence but defaults to a no-op. This keeps the core simple and dependency-free.

**Tradeoff:** Unbounded memory for long sessions with high traffic. Mitigated by a future SQLite backend that flushes frames on `FrameCapturedEvent`.

---

## Roadmap

### Near term

- **SQLite persistence** — implement `SqliteStorageBackend` using `aiosqlite`. Subscribe to `FrameCapturedEvent` and write frames as they arrive. The `Frame` and `SessionInfo` dataclasses map directly to table rows with no schema redesign needed.

- **TLS MITM** — wrap `asyncio.open_connection()` and `asyncio.start_server()` with `ssl.SSLContext`. The relay, framing, and intercept layers do not change at all; TLS is purely a transport concern in `core/proxy.py`.

- **HTTP/REST control API** — wrap `ProxyAPI` in an `aiohttp` or `FastAPI` server to expose session listing, intercept queue, and replay over HTTP/WebSocket. This enables a browser-based UI without any changes to the proxy core.

### Protocol layer

- **Protocol decoders** — implement `ProtocolDecoder` subclasses for specific protocols (e.g. HTTP/1.1, Redis, DNS). Register them in a `DECODER_REGISTRY` keyed by framer name or magic bytes.

- **Declarative protocol DSL** — define field layouts in YAML or JSON; auto-generate a `ProtocolDecoder` from the schema. No changes to the transport/framing/intercept layers required.

- **Protobuf / Thrift / Kaitai** — compile existing IDL schemas into `ProtocolDecoder` implementations. The interface (`decode(frame) -> ParsedMessage`) is simple enough to wrap any existing parser.

### UI

- **Terminal UI** — use `textual` or `prompt_toolkit` to build a Burp-like intercept queue view, session list, hex viewer, and in-place editor. All UI calls go through `ProxyAPI` — no direct access to internals.

- **Hex + parsed tree view** — combine the raw `frame.raw_bytes` hex dump with the structured `ParsedMessage.fields` tree for a Wireshark-style split view.

### Advanced features

- **Fuzzing hooks** — add a `FrameMutator` interface that sits between the intercept controller and the relay. `ReplayEngine.replay_session(modified_frames=...)` already supports targeted replacement; a mutator layer can automate this for coverage-guided or random fuzzing.

- **Differential replay** — replay the same session against two servers and compare responses frame-by-frame. Useful for regression testing after a fix.

- **Timed replay** — honour original inter-frame delays from the captured session, or inject custom delays, to reproduce timing-sensitive bugs.

- **Per-session / per-direction intercept rules** — filter expressions (e.g. "only intercept frames matching this regex") to reduce noise when analysing high-volume protocols.

- **Plugin / dissector system** — load custom `Framer` or `ProtocolDecoder` subclasses from external Python modules at startup, without modifying the core package.
