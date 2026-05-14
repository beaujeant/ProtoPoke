# Getting Started — Core Library

ProtoPoke's entire functionality is reachable from Python through one class:
`ProtoPokeAPI`. It is the same engine the terminal UI drives — the UI is just
one front end. This page is a high-level tour; the later pages
([Config](config.md), [Traffic](traffic.md), [Intercept](intercept.md),
[Forge](forge.md)) go deeper with more examples.

Everything is `asyncio`-based, so API calls happen inside an event loop.

## Set up a forwarder

A `ForwarderConfig` describes one proxy; `ProtoPokeAPI` takes a list of them.

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig

async def main():
    fwd = ForwarderConfig(
        name="Default",
        forwarder_type="tcp",        # "tcp" | "udp" | "socks5"
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
    )
    api = ProtoPokeAPI([fwd])

    await api.start()            # start all enabled forwarders
    # ... do work ...
    await api.stop()

asyncio.run(main())
```

Use `await api.serve_forever()` instead of `start()` to start everything and
block until `stop()` is called. See [Config](config.md) for every
`ForwarderConfig` field, transports, TLS, and projects.

## Watch the traffic

Subscribe to the event bus to react to sessions and frames as they happen:

```python
api.on_session_opened(lambda e: print(f"session: {e.session.id}"))
api.on_frame_captured(lambda e: print(f"frame:   {e.frame.raw_bytes.hex()}"))
```

Or poll the in-memory stores:

```python
for session in api.list_sessions():
    for frame in api.get_frames(session.id):
        print(frame.direction, frame.raw_bytes.hex())
```

How bytes are cut into frames (the **framer**) and decoded into named fields
(the **protocol definition**) is covered in [Traffic](traffic.md),
[Framers](../reference/framers.md), and
[Protocol Definitions](../reference/protocol-definitions.md).

## Intercept and rewrite

Turn on tamper mode and drive the intercept queue yourself:

```python
api.tamper_enabled = True

unit = await api.get_next_intercepted()
print(unit.frame.direction, unit.frame.raw_bytes.hex())

api.forward(unit.id)                                  # send unchanged
# api.drop(unit.id)                                   # discard
# api.modify_and_forward(unit.id, new_bytes=b"\x01")  # edit then send
```

To rewrite traffic *automatically*, add a replace rule:

```python
from protopoke.rules.rule import ReplaceRule

api.add_replace_rule(ReplaceRule.create(
    label="alice -> admin",
    pattern_str="61 6C 69 63 65",   # "alice"
    replacement=b"admin",
))
```

See [Intercept](intercept.md) for intercept rules, replace-rule types, and
[Custom Replace Scripts](../reference/replace-scripts.md).

## Forge traffic

Send a one-shot frame, replay a captured session, or run a playbook:

```python
# One-shot send
result = await api.send_frame(host="10.0.0.1", port=9090, data=b"\x01\x02")
print(result.received_bytes.hex())

# Replay a captured session
result = await api.forge_session(session_id)

# Run an ordered playbook
from protopoke.forge.models import Playbook, PlaybookFrame

pb = Playbook.create(label="Login", host="10.0.0.1", port=9090)
pb.frames = [
    PlaybookFrame.create(label="hello", raw_hex="01 00"),
    PlaybookFrame.create(label="auth",  raw_hex="02 {{TOKEN}}"),
]
run = await api.run_playbook(pb)
```

See [Forge](forge.md) for persistent sessions, field-level replay edits,
playbook variables, and injecting into live sessions.

## Where next

- [Config](config.md) — `ForwarderConfig`, transports, TLS, `ProjectManager`
- [Traffic](traffic.md) — sessions, events, decoding frames
- [Intercept](intercept.md) — tamper queue and rules
- [Forge](forge.md) — send, replay, playbooks
- Prefer the TUI? → [User Interface — Getting Started](../ui/getting-started.md)
