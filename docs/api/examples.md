# Examples

The `examples/` directory contains runnable scripts demonstrating key features.

## Simple Proxy

Basic proxy with event handlers that print session and frame activity:

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig

async def main():
    fwd = ForwarderConfig(
        name="Default",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
    )
    api = ProtoPokeAPI([fwd])

    # Subscribe to events
    api.on_session_opened(lambda e: print(f"Session opened: {e.session_id}"))
    api.on_session_closed(lambda e: print(f"Session closed: {e.session_id}"))
    api.on_frame_captured(lambda e: print(f"Frame captured: {e.frame_id}"))

    await api.start()
    await api.serve_forever()

asyncio.run(main())
```

See `examples/simple_proxy.py` for the full version.

## Intercept and Tamper

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig

async def main():
    fwd = ForwarderConfig(
        name="Default",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
    )
    api = ProtoPokeAPI([fwd])
    await api.start()

    # Intercept loop
    while True:
        unit = await api.get_next_intercepted()
        print(f"Direction: {unit.frame.direction}")
        print(f"Data: {unit.frame.raw_bytes.hex()}")

        # Forward all frames (modify as needed)
        api.forward(unit.id)

asyncio.run(main())
```

See `examples/tamper_demo.py` for a more complete example.

## Protocol-Aware Tamper

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig

async def main():
    fwd = ForwarderConfig(
        name="Default",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
        framer_name="length_prefix",
        framer_kwargs={"prefix_length": 2, "byte_order": "big"},
        protocol_definition_path="examples/protocols/chat.proto.yaml",
    )
    api = ProtoPokeAPI([fwd])
    await api.start()

    while True:
        unit, parsed = await api.get_next_intercepted_parsed()
        if parsed and parsed.message_type == "LoginRequest":
            # Change the username field — length fields are auto-recomputed
            api.modify_field_and_forward(unit.id, {"username": "admin"})
        else:
            api.forward(unit.id)

asyncio.run(main())
```

## Session Replay

```python
import asyncio
from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig

async def main():
    fwd = ForwarderConfig(
        name="Default",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
    )
    api = ProtoPokeAPI([fwd])
    await api.start()

    # ... capture some traffic first ...

    sessions = api.list_sessions()
    if sessions:
        result = await api.forge_session(sessions[0].id)
        for entry in result.entries:
            print(f"Sent: {entry.sent_bytes.hex()}")
            print(f"Received: {entry.received_bytes.hex()}")

    await api.stop()

asyncio.run(main())
```

## Example Protocol Definitions

### Chat Protocol

`examples/protocols/chat.proto.yaml` defines a fictional chat protocol with:

- Login request/response with enum status codes
- Chat messages with string payloads
- User list with array fields
- Disconnect with bitfield flags

### DNS Protocol

`examples/protocols/dns.proto.yaml` defines DNS message structure.

## Custom Framer

`examples/dns_framer.py` demonstrates a custom framer for DNS-over-TCP, which prefixes each DNS message with a 2-byte big-endian length.

`examples/frame_size_framer.py` shows another custom framer implementation.
