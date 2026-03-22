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
from protopoke.forge.engine import ForgeEngine

# One-shot send
result = await api.send_frame(
    host="10.0.0.1",
    port=9090,
    data=b"\x01\x00\x05admin",
)
print(result.response_bytes.hex())

# Open a persistent forge session (keeps the TCP connection open)
forge_session = await api.open_forge_session(host="10.0.0.1", port=9090)
result = await api.send_on_forge_session(forge_session.id, data=b"\x01\x00\x05admin")
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
    result = await api.forge_session(session_id)
    for entry in result.entries:
        print(f"Sent: {entry.sent_bytes.hex()}")
        print(f"Received: {entry.received_bytes.hex()}")
    ```

=== "MCP"

    ```
    forge_session(session_id="<uuid>")
    ```

### Replay with Field Edits

When a protocol definition is loaded, you can replay a session while overriding specific field values. Length fields are automatically recomputed.

=== "Python API"

    ```python
    result = await api.replay_with_field_edits(
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

    playbook = Playbook(
        name="Login sequence",
        frames=[
            PlaybookFrame(data=b"\x01\x00\x05admin", label="Login"),
            PlaybookFrame(data=b"\x03", label="List users"),
        ],
        host="10.0.0.1",
        port=9090,
    )
    ```

=== "MCP"

    ```
    create_playbook(name="Login sequence", host="10.0.0.1", port=9090, frames=[...])
    run_playbook(playbook_id="<uuid>")
    ```

### Variables

Playbook frames support `{{VARIABLE}}` placeholders that are resolved at runtime from the global variable store:

```python
api.variables["TOKEN"] = "aabbccdd"

frame = PlaybookFrame(data=b"\x02{{TOKEN}}", label="Auth with token")
```

Variables are hex-encoded byte strings. They are shared across all pipelines (intercept, forge, playbooks) so that state captured by a script rule can flow into subsequent operations.

## Injecting into Live Sessions

You can inject frames into active proxy sessions:

```python
# Inject a frame to the upstream server on an existing session
await api.inject_to_server(session_id, data=b"\x01\x02\x03")

# Inject a frame to the client
await api.inject_to_client(session_id, data=b"\x04\x05\x06")
```
