# Forge

Forge is how the library *generates* traffic: one-shot sends, persistent
forge sessions, captured-session replay, ordered playbooks, and injection
into live proxy sessions.

## One-shot send

`send_frame()` opens a connection, sends bytes, collects the reply, and
returns a `SendResult` (`sent_bytes`, `received_bytes`, `response_packets`,
`success`, `error`).

```python
result = await api.send_frame(host="10.0.0.1", port=9090, data=b"\x01\x00\x05admin")
print(result.received_bytes.hex())
for pkt in result.response_packets:        # individual framed reply chunks
    print(pkt.hex())
```

`send_frame()` can also **reuse an existing forge or proxy session** instead
of opening a fresh connection — pass `source_session_id=<id>`. Works for TCP,
SOCKS5, and UDP.

## Persistent forge sessions

Keep a connection open across multiple sends:

```python
sid = await api.open_forge_session(host="10.0.0.1", port=9090, tls=False)
r1  = await api.send_on_forge_session(sid, data=b"HELLO\r\n")
r2  = await api.send_on_forge_session(sid, data=b"LIST\r\n")
await api.terminate_session(sid)
```

## Replaying a captured session

`forge_session()` re-sends a captured session's client→server frames against
a target and returns a `ForgeResult` wrapping a new replayed `Session`.

```python
result = await api.forge_session(session_id)
print(result.success, result.error)
for frame in result.frames_sent():
    print("sent:    ", frame.raw_bytes.hex())
for frame in result.frames_received():
    print("received:", frame.raw_bytes.hex())
```

With a protocol definition loaded you can replay while overriding specific
fields — length fields are recomputed automatically:

```python
result = await api.forge_session_with_field_edits(
    session_id,
    field_edits={"LoginRequest": {"username": "admin", "password": b"\x00" * 16}},
    server_host="newhost.example.com",      # optional: replay against a different target
)
```

## Playbooks

A `Playbook` is an ordered list of `PlaybookFrame`s. It either opens a fresh
connection (`host`/`port`/`tls`/`transport`) or reuses an existing proxy
session (`source_session_id`). `run_playbook()` executes the frames in order
and auto-manages the connection.

```python
from protopoke.forge.models import Playbook, PlaybookFrame

playbook = Playbook.create(
    label="Login sequence",
    host="10.0.0.1",
    port=9090,
    transport="tcp",                # "tcp" (default) or "udp"
)
playbook.frames = [
    # raw_hex is a space-separated hex string; may contain {{VAR}} tokens.
    PlaybookFrame.create(label="Login",      raw_hex="01 00 05 61 64 6d 69 6e"),
    PlaybookFrame.create(label="List users", raw_hex="03"),
]

run = await api.run_playbook(playbook)      # -> PlaybookRun
```

Each `PlaybookFrame` also has a `direction` — `"client_to_server"` (send
toward the server) or `"server_to_client"` (inject toward the client).

### Variables

Playbook frames support `{{VARIABLE}}` placeholders resolved at runtime from
the shared variable store. The store is shared across every pipeline
(intercept, forge, playbooks), so a value captured by a
[script replace rule](../reference/replace-scripts.md) flows straight into a
playbook frame.

```python
api.variables["TOKEN"] = "aabbccdd"        # hex-encoded byte string
frame = PlaybookFrame.create(label="Auth with token", raw_hex="02 {{TOKEN}}")
```

## Injecting into live sessions

Inject a frame into an active proxy session (TCP, SOCKS5, or UDP):

```python
await api.inject_to_server(session_id, data=b"\x01\x02\x03")
await api.inject_to_client(session_id, data=b"\x04\x05\x06")
```

This is what makes **half-open sessions** useful. When the client
disconnects, the session moves to `ONLY_SERVER` but the upstream stays open,
so `inject_to_server()` keeps working; likewise `inject_to_client()` after
the server drops. The session reaches `CLOSED` only once both sides are gone
or you call `terminate_session()`.

## Next

- [Custom Replace Scripts](../reference/replace-scripts.md) — populate `{{VARIABLE}}` values
- [Fuzzing (experimental)](../reference/fuzzing.md)
- [User Interface — Forge](../ui/forge.md) — the same, in the TUI
