# Python API

ProtoPoke's entire functionality is accessible through the `ProxyAPI` class, which serves as the single public facade for all proxy operations.

## Basic Setup

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ForwarderConfig, ProxyConfig

async def main():
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
    )
    forwarders = [ForwarderConfig(name="Default", enabled=True, config=config)]
    api = ProxyAPI(forwarders)

    await api.start()

    # ... do work ...

    await api.stop()

asyncio.run(main())
```

## Configuration

`ProxyConfig` controls all proxy behaviour:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_host` | str | `"127.0.0.1"` | Bind address |
| `listen_port` | int | `8080` | Listen port |
| `upstream_host` | str | `"127.0.0.1"` | Target host |
| `upstream_port` | int | `9090` | Target port |
| `connect_timeout` | float | — | Upstream connection timeout |
| `read_buffer_size` | int | — | Read buffer size |
| `max_sessions` | int | `0` | Max concurrent sessions (0 = unlimited) |
| `tamper_enabled` | bool | `False` | Enable intercept on startup |
| `framer_name` | str | `"raw"` | Framer: `raw`, `delimiter`, `length_prefix`, `line` |
| `framer_kwargs` | dict | `{}` | Framer-specific parameters |
| `custom_framer_path` | str | `None` | Path to custom framer script |
| `log_level` | str | `"INFO"` | Logging level |
| `tls_listen` | bool | `False` | Enable TLS MITM on client side |
| `tls_upstream` | bool | `False` | Connect to upstream over TLS |
| `ca_cert_path` | str | `None` | Custom CA certificate path |
| `ca_key_path` | str | `None` | Custom CA key path |
| `protocol_definition_path` | str | `None` | Protocol definition file path |

Configs can be serialised:

```python
# Save to JSON
config.save("proxy_config.json")

# Load from JSON
config = ProxyConfig.load("proxy_config.json")
```

## Multi-Forwarder Setup

Multiple forwarders let you proxy several targets simultaneously. All share a single session registry, event bus, tamper controller, and rules engine.

```python
forwarders = [
    ForwarderConfig(name="Service A", enabled=True, config=ProxyConfig(
        listen_port=8080, upstream_host="10.0.0.1", upstream_port=9090,
    )),
    ForwarderConfig(name="Service B", enabled=True, config=ProxyConfig(
        listen_port=8081, upstream_host="10.0.0.2", upstream_port=9091,
    )),
]
api = ProxyAPI(forwarders)
await api.start()
```

## Session Management

```python
# List all sessions
sessions = api.list_sessions()

# List active sessions only
active = api.list_active_sessions()

# Get session details
session = api.get_session(session_id)

# Get frames for a session
frames = api.get_frames(session_id)
```

## Tamper Control

```python
# Enable/disable tampering
api.tamper_enabled = True

# Wait for next intercepted frame
unit = await api.get_next_intercepted()

# Issue verdicts
api.forward(unit.id)
api.drop(unit.id)
api.modify_and_forward(unit.id, new_bytes=b"\x01\x02\x03")
api.modify_field_and_forward(unit.id, {"field_name": "new_value"})

# Get intercepted frame with parsed message
unit, parsed = await api.get_next_intercepted_parsed()

# List pending intercepted frames
pending = api.list_intercepted()

# Check pending count
count = api.pending_count()
```

## Rules

```python
from protopoke.rules.rule import ReplaceRule, InterceptRule, RuleAction
from protopoke.models import Direction

# Add a replace rule
rule = ReplaceRule(name="Swap user", find=b"alice", replace=b"admin")
api.add_replace_rule(rule)

# Add an intercept rule
irule = InterceptRule(
    name="Hold logins",
    pattern=b"\x01",
    direction=Direction.CLIENT_TO_SERVER,
    action=RuleAction.INTERCEPT,
)
api.add_intercept_rule(irule)

# List / remove / reorder rules
api.list_replace_rules()
api.remove_replace_rule(rule.id)
```

## Protocol Decoding

```python
# Load from file
api.set_protocol_file("myproto.yaml")

# Load from dict
api.set_protocol_dict({"name": "MyProto", "endianness": "big", "messages": [...]})

# Decode a frame
parsed = api.decode_frame(session_id, frame_id)
print(parsed.message_type)
print(parsed.fields)
```

## Forge and Replay

```python
# One-shot send
result = await api.send_frame(host="10.0.0.1", port=9090, data=b"\x01\x02")

# Replay a captured session
result = await api.forge_session(session_id)

# Replay with field edits
result = await api.replay_with_field_edits(
    session_id,
    field_edits={"LoginRequest": {"username": "admin"}},
)

# Inject into a live session
await api.inject_to_server(session_id, data=b"\x01")
await api.inject_to_client(session_id, data=b"\x02")
```

## Fuzzing

```python
from protopoke.fuzzing.mutators.raw import BitFlipMutator, KnownBadMutator

results = await api.fuzz_session(
    session_id=session_id,
    mutators=[BitFlipMutator(), KnownBadMutator()],
    iterations=100,
    stop_on_crash=True,
)

for r in results:
    if r.is_interesting:
        print(f"Anomaly: {r.anomaly_type}")
```

## Event Bus

Subscribe to proxy events for real-time notifications:

```python
# Session opened
api.on_session_opened(lambda event: print(f"New session: {event.session_id}"))

# Session closed
api.on_session_closed(lambda event: print(f"Session closed: {event.session_id}"))

# Frame captured
api.on_frame_captured(lambda event: print(f"Frame: {event.frame_id}"))
```

## Storage Backends

By default, ProtoPoke stores sessions in memory. A SQLite backend is available:

```python
from protopoke.storage.sqlite import SqliteStorageBackend

storage = SqliteStorageBackend("sessions.db")
api = ProxyAPI(forwarders, storage=storage)
```

You can implement custom backends by subclassing `StorageBackend`:

```python
from protopoke.storage.base import StorageBackend

class MyBackend(StorageBackend):
    async def save_session(self, session): ...
    async def load_session(self, session_id): ...
    async def list_sessions(self): ...
    async def save_frame(self, frame): ...
    async def load_frames(self, session_id): ...
```
