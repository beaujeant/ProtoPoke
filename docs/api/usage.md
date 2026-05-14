# Python API

ProtoPoke's entire functionality is accessible through the `ProtoPokeAPI` class, which serves as the single public facade for all proxy operations.

## Basic Setup

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig

async def main():
    fwd = ForwarderConfig(
        name="Default",
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
    )
    api = ProtoPokeAPI([fwd])

    await api.start()

    # ... do work ...

    await api.stop()

asyncio.run(main())
```

## Configuration

`ForwarderConfig` controls all forwarder behaviour. Each forwarder is configured with a single flat dataclass:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | str | `"Forwarder"` | Human-readable label |
| `enabled` | bool | `True` | Include in "Start All" |
| `forwarder_type` | str/`ForwarderType` | `"tcp"` | Transport: `"tcp"`, `"udp"`, or `"socks5"` |
| `listen_host` | str | `"127.0.0.1"` | Bind address |
| `listen_port` | int | `8080` | Listen port |
| `upstream_host` | str | `"127.0.0.1"` | Target host (ignored by SOCKS5 — target comes from the handshake) |
| `upstream_port` | int | `9090` | Target port (ignored by SOCKS5) |
| `connect_timeout` | float | `10.0` | Upstream connection timeout |
| `read_buffer_size` | int | `4096` | Read buffer size |
| `socks_auth_user` | str | `None` | SOCKS5 username; `None` = advertise no-auth |
| `socks_auth_pass` | str | `None` | SOCKS5 password |
| `max_sessions` | int | `0` | Max concurrent sessions (0 = unlimited) |
| `keep_upstream_on_client_disconnect` | bool | `True` | Keep the upstream connection open after the client disconnects (session → `ONLY_SERVER`). `False` = legacy TCP half-close. TCP/SOCKS5 only |
| `keep_client_on_server_disconnect` | bool | `True` | Keep the client connection writable after the upstream server disconnects (session → `ONLY_CLIENT`). `False` = legacy TCP half-close. TCP/SOCKS5 only |
| `tamper_enabled` | bool | `False` | Enable intercept on startup |
| `framer_name` | str | `"raw"` | Framer: `raw`, `delimiter`, `length_prefix`, `line` (UDP always uses `raw`) |
| `framer_kwargs` | dict | `{}` | Framer-specific parameters |
| `custom_framer_path` | str | `None` | Path to custom framer script |
| `log_level` | str | `"INFO"` | Logging level |
| `tls_listen` | bool | `False` | Enable TLS MITM on client side (rejected for UDP/SOCKS5) |
| `tls_upstream` | bool | `False` | Connect to upstream over TLS |
| `ca_cert_path` | str | `None` | Custom CA certificate path (auto-generated at `~/.protopoke/ca.crt` when unset) |
| `ca_key_path` | str | `None` | Custom CA key path (auto-generated at `~/.protopoke/ca.key` when unset) |
| `tls_cert_path` | str | `None` | Manual leaf-cert override (skips the auto-CA) |
| `tls_key_path` | str | `None` | Private key for `tls_cert_path` |
| `protocol_definition_path` | str | `None` | Protocol definition file path |

### Transport Types

Each forwarder picks a transport via `forwarder_type`:

```python
# Plain TCP proxy (default)
tcp = ForwarderConfig(name="tcp", listen_port=8080,
                      upstream_host="10.0.0.1", upstream_port=9090)

# UDP proxy — one session per (client_host, client_port) flow.
# Always uses the raw framer; cannot use tls_listen.
udp = ForwarderConfig(name="dns", forwarder_type="udp", listen_port=5353,
                      upstream_host="1.1.1.1", upstream_port=53)

# SOCKS5 proxy — the upstream target is discovered from each client's
# CONNECT request; upstream_host/upstream_port are ignored.
socks = ForwarderConfig(name="socks", forwarder_type="socks5",
                        listen_port=1080,
                        socks_auth_user="user", socks_auth_pass="pass")
```

Configs can be serialised:

```python
# Save to JSON
fwd.save("forwarder_config.json")

# Load from JSON
fwd = ForwarderConfig.load("forwarder_config.json")
```

## Multi-Forwarder Setup

Multiple forwarders let you proxy several targets simultaneously. All share a single session registry, event bus, tamper controller, and rules engine.

```python
forwarders = [
    ForwarderConfig(
        name="Service A",
        listen_port=8080, upstream_host="10.0.0.1", upstream_port=9090,
    ),
    ForwarderConfig(
        name="Service B",
        listen_port=8081, upstream_host="10.0.0.2", upstream_port=9091,
    ),
]
api = ProtoPokeAPI(forwarders)
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

# Decode a single Frame (from get_frames() or a tampered unit)
frame = api.get_frames(session_id)[0]
parsed = api.decode_frame(frame)
print(parsed.message_type)
print(parsed.fields)

# Or decode every frame in a session at once
messages = api.decode_session_frames(session_id)
```

## Forge and Replay

```python
# One-shot send
result = await api.send_frame(host="10.0.0.1", port=9090, data=b"\x01\x02")

# Replay a captured session — returns a ForgeResult
result = await api.forge_session(session_id)
print(result.replayed_session.id, result.success)

# Replay with per-message-type field edits
result = await api.forge_session_with_field_edits(
    session_id,
    field_edits={"LoginRequest": {"username": "admin"}},
)

# Inject into a live proxy session (works for TCP, SOCKS5, and UDP).
# Handy on ONLY_SERVER / ONLY_CLIENT sessions where one side has gone
# but the other is still open.
await api.inject_to_server(session_id, data=b"\x01")
await api.inject_to_client(session_id, data=b"\x02")
```

## Fuzzing

```python
from protopoke.fuzzing.mutators.raw import BitFlipMutator, KnownBadMutator

# fuzz_session() returns a FuzzCampaign with all results populated.
campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[BitFlipMutator(), KnownBadMutator()],
    iterations=100,
    stop_on_crash=True,
)

for r in campaign.interesting_results:
    print(f"iteration {r.iteration} ({r.mutator_name}): "
          f"reset={r.connection_reset} timed_out={r.timed_out} "
          f"sent={r.mutated_bytes.hex()}")
```

## Event Bus

Subscribe to proxy events for real-time notifications:

Each event carries a `session` (a `SessionInfo`) and, for frame events, a
`frame` (a `Frame`):

```python
# Session opened
api.on_session_opened(lambda event: print(f"New session: {event.session.id}"))

# Session closed
api.on_session_closed(lambda event: print(f"Session closed: {event.session.id}"))

# Frame captured
api.on_frame_captured(lambda event: print(f"Frame: {event.frame.id}"))

# Session updated (e.g. transitioned to ONLY_SERVER / ONLY_CLIENT)
api.on_session_updated(lambda event: print(f"Updated: {event.session.id}"))

# Upstream connection failed
api.on_upstream_connection_failed(lambda event: print(f"Failed: {event.error}"))
```

## Persistence

Sessions and frames live in memory for the lifetime of the process — there
is no database layer. To persist a working set, save a project file with
`ProjectManager` (see the [Projects guide](../guide/projects.md)), which
bundles forwarders, rules, playbooks, captured traffic, display filters, and
MCP settings into a single `.pp` ZIP archive.
