# Forge & Replay

ProtoPoke provides two complementary features for sending traffic to a target server:

- **Forge** — hand-craft frames from scratch and send them directly
- **Replay** — re-send captured session traffic, optionally modifying fields

## Forge

Forge lets you construct arbitrary frames and send them to a target, similar to Burp Suite's Repeater.

### Using the TUI

1. Switch to the **Forge** tab (++f4++)
2. Enter hex bytes in the editor
3. Set the target host and port
4. Click **Send**
5. View the response in the send history

You can also send any captured frame to Forge from the Traffic tab using ++ctrl+f++.

### Python API

```python
# One-shot send — returns a SendResult
result = await api.send_frame(
    host="10.0.0.1",
    port=9090,
    data=b"\x01\x00\x05admin",
)
print(result.received_bytes.hex())   # all reply bytes, concatenated
for pkt in result.response_packets:  # individual framed reply chunks
    print(pkt.hex())

# Open a persistent forge session (keeps the connection open)
forge_session = await api.open_forge_session(host="10.0.0.1", port=9090)
result = await api.send_on_forge_session(forge_session.id, data=b"\x01\x00\x05admin")

# send_frame() can also reuse an existing forge or proxy session instead of
# opening a fresh connection — pass source_session_id=<session id>. This
# works for TCP, SOCKS5, and UDP sessions.
```

### MCP

```
send_frame(host="10.0.0.1", port=9090, data_hex="01000561646d696e")
```

## Replay

Replay re-sends a captured session's client-to-server frames against a target server, capturing the responses.

### Basic Replay

=== "Python API"

    ```python
    # Returns a ForgeResult wrapping a new "replayed" Session.
    result = await api.forge_session(session_id)
    print(f"success={result.success} error={result.error}")
    for frame in result.frames_sent():
        print(f"Sent:     {frame.raw_bytes.hex()}")
    for frame in result.frames_received():
        print(f"Received: {frame.raw_bytes.hex()}")
    ```

=== "MCP"

    ```
    forge_session(session_id="<uuid>")
    ```

### Replay with Field Edits

When a protocol definition is loaded, you can replay a session while overriding specific field values. Length fields are automatically recomputed.

=== "Python API"

    ```python
    result = await api.forge_session_with_field_edits(
        session_id=session_id,
        field_edits={
            "LoginRequest": {"username": "admin", "password": b"\x00" * 16},
        },
    )
    ```

=== "MCP"

    ```
    replay_with_field_edits(
        session_id="<uuid>",
        field_edits={"LoginRequest": {"username": "admin"}}
    )
    ```

## Playbooks

Playbooks are ordered sequences of frames with variable substitution. They let you build reusable test sequences.

### Creating a Playbook

=== "Python API"

    ```python
    from protopoke.forge.models import Playbook, PlaybookFrame

    playbook = Playbook.create(
        label="Login sequence",
        host="10.0.0.1",
        port=9090,
        transport="tcp",   # "tcp" (default) or "udp"
    )
    playbook.frames = [
        # raw_hex is a space-separated hex string, may contain {{VAR}} tokens.
        PlaybookFrame.create(label="Login",      raw_hex="01 00 05 61 64 6d 69 6e"),
        PlaybookFrame.create(label="List users", raw_hex="03"),
    ]
    ```

    Each `PlaybookFrame` also has a `direction` (`"client_to_server"` —
    send toward the server — or `"server_to_client"` — inject toward the
    client). A `Playbook` can target a fresh connection (`host`/`port`/
    `tls`/`transport`) or an existing proxy session via `source_session_id`.

=== "MCP"

    ```
    create_playbook(name="Login sequence", host="10.0.0.1", port=9090, frames=[...])
    run_playbook(playbook_id="<uuid>")
    ```

### Variables

Playbook frames support `{{VARIABLE}}` placeholders that are resolved at runtime from the global variable store:

```python
api.variables["TOKEN"] = "aabbccdd"

frame = PlaybookFrame.create(label="Auth with token", raw_hex="02 {{TOKEN}}")
```

Variables are hex-encoded byte strings. They are shared across all pipelines (intercept, forge, playbooks) so that state captured by a script rule can flow into subsequent operations.

## Injecting into Live Sessions

You can inject frames into active proxy sessions — TCP, SOCKS5, or UDP:

```python
# Inject a frame to the upstream server on an existing session
await api.inject_to_server(session_id, data=b"\x01\x02\x03")

# Inject a frame to the client
await api.inject_to_client(session_id, data=b"\x04\x05\x06")
```

This is especially useful for **half-open sessions**: when the client
disconnects the session moves to `ONLY_SERVER` but the upstream connection
stays open, so `inject_to_server()` keeps working. Likewise, when the
upstream server disconnects the session moves to `ONLY_CLIENT` and
`inject_to_client()` keeps working. The session only reaches `CLOSED` once
both sides are gone or you call `api.terminate_session(session_id)`.
