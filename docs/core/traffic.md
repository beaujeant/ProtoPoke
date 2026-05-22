---
title: "Traffic"
---

Captured traffic lives in an in-memory session registry. The library gives
you two ways to consume it: **poll** the registry, or **subscribe** to the
event bus for push notifications.

## Querying sessions and frames

```python
# All sessions (active and closed)
for session in api.list_sessions():
    print(session.id, session.state, session.frame_count)

# Active sessions only
active = api.list_active_sessions()

# One session's details
session = api.get_session(session_id)

# Frames for a session, optionally filtered by direction
from protopoke.models import Direction
frames = api.get_frames(session_id)
c2s    = api.get_frames(session_id, direction=Direction.CLIENT_TO_SERVER)

for frame in frames:
    print(frame.direction, frame.raw_bytes.hex())
```

Sessions can also be closed or removed:

```python
await api.terminate_session(session_id)   # force-close an active session
api.delete_session(session_id)            # remove it from the registry
```

## Subscribing to events

The event bus pushes events from the relay/proxy tasks. Each handler
receives an event object; frame events also carry the `frame`.

```python
api.on_session_opened(lambda e:  print(f"opened:  {e.session.id}"))
api.on_session_closed(lambda e:  print(f"closed:  {e.session.id}"))
api.on_session_updated(lambda e: print(f"updated: {e.session.id} -> {e.session.state}"))
api.on_frame_captured(lambda e:  print(f"frame:   {e.frame.raw_bytes.hex()}"))
api.on_upstream_connection_failed(lambda e: print(f"failed:  {e.error}"))
```

`on_session_updated` fires when a session changes mid-life — for example
transitioning to `ONLY_SERVER` / `ONLY_CLIENT` after a half-close.

## Framing

The **framer** cuts the raw byte stream into discrete frames. It is set per
forwarder via `framer_name` / `framer_kwargs` / `custom_framer_path` on
`ForwarderConfig`, and can be hot-swapped on running sessions:

```python
# Hot-swap the framer on every session of a forwarder
reframed = api.set_framer(
    "length_prefix",
    framer_kwargs={"prefix_length": 2, "byte_order": "big"},
    forwarder_name="Default",
)
print(f"{reframed} sessions re-framed")
```

Built-in framers, their parameters, and the custom-framer script API are
covered in full in [Framers](/reference/framers).

## Decoding frames

Attach a **protocol definition** to decode frames into named, typed fields:

```python
# Load from a YAML/JSON file
api.set_protocol_file("examples/protocols/chat.proto.yaml")

# ...or from a dict
api.set_protocol_dict({"name": "MyProto", "endianness": "big", "messages": [...]})

# Decode a single frame
frame  = api.get_frames(session_id)[0]
parsed = api.decode_frame(frame)
print(parsed.message_type)          # e.g. "LoginRequest"
print(parsed.as_dict())             # {"opcode": 1, "username": "admin", ...}

# Decode every frame in a session
messages = api.decode_session_frames(session_id)
```

A `ParsedMessage` exposes `message_type`, `protocol_name`, `field_by_name()`,
and `as_dict()`. Field objects carry `value`, `display_value`, `offset`, and
`size`. The full DSL — message matching, field types, length expressions —
is documented in [Protocol Definitions](/reference/protocol-definitions).

## Next

- [Intercept](/core/intercept) — the tamper queue and rules
- [Framers](/reference/framers) / [Protocol Definitions](/reference/protocol-definitions)
- [User Interface — Traffic](/ui/traffic) — the same, in the TUI
