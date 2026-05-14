# Framing

TCP is a byte stream — the OS delivers bytes in arbitrary chunks that bear no relation to application message boundaries. A single `read()` may return half a message, exactly one message, or three messages fused together.

The framer is the **first processing phase** for every byte that arrives on a proxied connection. Its job is to cut the raw stream into discrete, atomic units called **frames** — one frame = one complete application-level message. Everything downstream (tamper, protocol parsing, forge, replay, fuzzing) operates on frames.

ProtoPoke runs one framer instance per direction per session:

```
client ──bytes──▶ [client→server framer] ──frames──▶ tamper / parse / log
server ──bytes──▶ [server→client framer] ──frames──▶ tamper / parse / log
```

!!! note "UDP forwarders"
    Framing only applies to the stream-oriented transports (TCP and SOCKS5).
    UDP is already message-oriented — one datagram is one frame — so UDP
    forwarders always use the `raw` framer and the framer selector is
    disabled for them.

## Choosing a Framer

| Protocol style | Framer | Example protocols |
|---------------|--------|-------------------|
| Unknown / first look | `raw` (default) | Any — just observe raw bytes |
| Line-based text | `delimiter` with `\r\n` or `\n` | HTTP headers, SMTP, FTP, Redis |
| Null-terminated | `delimiter` with `\x00` | C-string protocols |
| Binary with length header | `length_prefix` | Most game/chat/custom binary protocols |
| Line-oriented with mixed endings | `line` | HTTP/1.x, any `\r\n` or `\n` protocol |
| Custom boundary logic | Custom framer script | Anything else |

!!! tip "How to find the right framer"
    Capture a few frames with `raw` first, open them in a hex editor, and look for patterns. A 2- or 4-byte integer at the start whose value matches the remaining byte count is a length prefix. Repeated `\r\n` or `\x00` terminations mean a delimiter framer.

## Built-in Framers

### `raw` (default)

Every `read()` chunk becomes one frame immediately. No buffering or boundary detection. Good for initial observation; unreliable for parsing.

=== "Python API"

    ```python
    fwd = ForwarderConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        # framer_name defaults to "raw"
    )
    ```

=== "TUI"

    Config tab → Framer: `raw`

### `delimiter`

Accumulates bytes until a configurable byte sequence appears, then emits everything before it as one frame. The delimiter is consumed and not included in the frame.

=== "Python API"

    ```python
    # Split on CRLF
    fwd = ForwarderConfig(
        ...,
        framer_name="delimiter",
        framer_kwargs={"delimiter": b"\r\n"},
    )

    # Split on null byte
    fwd = ForwarderConfig(
        ...,
        framer_name="delimiter",
        framer_kwargs={"delimiter": b"\x00"},
    )
    ```

=== "TUI"

    Config tab → Framer: `delimiter` → set delimiter bytes

### `length_prefix`

Reads a fixed-size integer header that declares the payload length, buffers until that many bytes arrive, then emits the full `prefix + payload` as one frame.

=== "Python API"

    ```python
    # 4-byte big-endian length field
    fwd = ForwarderConfig(
        ...,
        framer_name="length_prefix",
        framer_kwargs={"prefix_length": 4, "byte_order": "big"},
    )

    # 2-byte little-endian, length field at offset 3, add 6 to include header
    fwd = ForwarderConfig(
        ...,
        framer_name="length_prefix",
        framer_kwargs={
            "prefix_length": 2,
            "byte_order": "little",
            "prefix_offset": 3,
            "length_add": 6,
        },
    )
    ```

=== "TUI"

    Config tab → Framer: `length_prefix` → configure prefix length, byte order, offset, and length adjustment

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `prefix_length` | int | — | Size of the length field: 1, 2, 4, or 8 bytes |
| `byte_order` | str | `"big"` | `"big"` or `"little"` |
| `prefix_offset` | int | `0` | Byte offset where the length field starts |
| `length_add` | int | `0` | Constant added to the length value (to include header bytes) |

### `line`

Convenience wrapper around `delimiter` that splits on `\r\n` and also accepts bare `\n`.

```python
fwd = ForwarderConfig(..., framer_name="line")
```

## Custom Framer

When none of the built-in framers fit, write a Python script with two functions. No imports from ProtoPoke are needed.

### Loading a Custom Framer

=== "Python API"

    ```python
    fwd = ForwarderConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        custom_framer_path="/path/to/my_framer.py",
    )
    ```

=== "TUI"

    Config tab → Edit Framer → Custom → Script path

`custom_framer_path` takes precedence over `framer_name`.

### Required Functions

```python
def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    """Called when bytes arrive. Return complete frames, or [] if more data is needed."""
    ...

def on_flush(state: dict, direction: str) -> list[bytes]:
    """Called when the connection closes. Return any remaining buffered data."""
    ...
```

**Parameters:**

| Argument | Type | Description |
|----------|------|-------------|
| `data` | `bytes` | Raw bytes from the latest `read()` call |
| `state` | `dict` | Mutable dict shared between both directions for this session; persists for the connection lifetime |
| `direction` | `str` | `"c2s"` (client → server) or `"s2c"` (server → client) |

### Example: DNS-over-TCP Framer

DNS over TCP prefixes each DNS message with a 2-byte big-endian length field:

```python
import struct

def on_data(data, state, direction):
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    frames = []
    while len(buf) >= 2:
        msg_len = struct.unpack("!H", buf[:2])[0]
        total = 2 + msg_len
        if len(buf) < total:
            break
        frames.append(bytes(buf[:total]))
        del buf[:total]
    return frames

def on_flush(state, direction):
    buf = state.get(direction, b"")
    return [bytes(buf)] if buf else []
```

See `examples/dns_framer.py` for a more complete example with error handling.
