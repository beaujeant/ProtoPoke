# Authoring a Framer

A **framer** cuts a raw TCP byte stream into discrete **frames**, where one
frame is one complete application-level message. Everything downstream
(tamper, protocol parsing, forge, replay, fuzzing) operates on frames, so
choosing or writing the right framer is the very first reverse-engineering
step.

ProtoPoke runs one framer instance **per direction per session**:

```
client ──bytes──▶ [client→server framer] ──frames──▶ tamper / parse / log
server ──bytes──▶ [server→client framer] ──frames──▶ tamper / parse / log
```

UDP forwarders do not use framers — one datagram is always one frame, so
UDP always uses the built-in `raw` framer.

## Choosing a Framer

| Protocol style                | Framer                             | Example protocols                |
|-------------------------------|------------------------------------|----------------------------------|
| Unknown / first look          | `raw` (default)                    | Any — just observe raw bytes     |
| Line-based text               | `delimiter` with `\r\n` or `\n`    | HTTP headers, SMTP, FTP, Redis   |
| Null-terminated               | `delimiter` with `\x00`            | C-string protocols               |
| Binary with length header     | `length_prefix`                    | Most game/chat/custom binary     |
| Line-oriented, mixed endings  | `line`                             | HTTP/1.x                         |
| Custom boundary logic         | Custom framer script               | Anything else                    |

**Heuristic for picking one:** capture a few frames with `raw` first, open
them in a hex editor, and look for patterns. A 2- or 4-byte integer at the
start whose value matches the remaining byte count is a length prefix.
Repeated `\r\n` or `\x00` terminations mean a delimiter framer.

## Built-in Framers

### `raw` (default)

Every `read()` chunk becomes one frame immediately. No buffering, no
boundary detection. Good for initial observation; unreliable for parsing
because TCP may coalesce or split messages arbitrarily.

```python
fwd = ForwarderConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    # framer_name defaults to "raw"
)
```

### `delimiter`

Accumulates bytes until a configurable byte sequence appears, then emits
everything before it as one frame. The delimiter is consumed and **not**
included in the frame.

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

### `length_prefix`

Reads a fixed-size integer header that declares the payload length, buffers
until that many bytes arrive, then emits the full `prefix + payload` as one
frame.

```python
# 4-byte big-endian length field at offset 0
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

Parameters:

| Parameter        | Type | Default | Description                                              |
|------------------|------|---------|----------------------------------------------------------|
| `prefix_length`  | int  | —       | Size of the length field: 1, 2, 4, or 8 bytes            |
| `byte_order`     | str  | `"big"` | `"big"` or `"little"`                                    |
| `prefix_offset`  | int  | `0`     | Byte offset where the length field starts                |
| `length_add`     | int  | `0`     | Constant added to the length value (e.g. to include header) |

### `line`

Convenience wrapper around `delimiter` that splits on `\r\n` and also
accepts bare `\n`.

```python
fwd = ForwarderConfig(..., framer_name="line")
```

## Custom Framer Scripts

When none of the built-ins fit, write a Python script with two functions.
No imports from ProtoPoke are required.

### Loading

```python
fwd = ForwarderConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    custom_framer_path="/path/to/my_framer.py",
)
```

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

Parameters:

| Argument    | Type    | Description                                                                |
|-------------|---------|----------------------------------------------------------------------------|
| `data`      | `bytes` | Raw bytes from the latest `read()` call                                     |
| `state`     | `dict`  | Mutable dict shared between both directions for this session; persists for the connection lifetime |
| `direction` | `str`   | `"c2s"` (client → server) or `"s2c"` (server → client)                       |

### Skeleton

A minimal length-prefix-style custom framer with per-direction buffers:

```python
def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    buffers = state.setdefault("buffers", {"c2s": b"", "s2c": b""})
    buffers[direction] += data

    frames = []
    while True:
        buf = buffers[direction]
        if len(buf) < 4:
            break                              # not enough for header
        payload_len = int.from_bytes(buf[:4], "big")
        total = 4 + payload_len
        if len(buf) < total:
            break                              # wait for full payload
        frames.append(buf[:total])
        buffers[direction] = buf[total:]
    return frames


def on_flush(state: dict, direction: str) -> list[bytes]:
    buffers = state.get("buffers", {})
    leftover = buffers.get(direction, b"")
    return [leftover] if leftover else []
```

### Authoring Tips

- **Always return a list**, even for a single frame: `return [my_frame]`.
- **Never block or call I/O**: `on_data` runs on the asyncio event loop.
- **Use `state`, not module globals**: globals are shared across all
  sessions and forwarders; `state` is per-session.
- **Buffer per direction**: server and client streams interleave through
  the same `state` dict. Key your buffer by `direction`.
- **Handle short reads**: TCP can deliver as little as one byte. Be ready
  for repeated `on_data(b"\x01")` calls that build up to a full frame.
- **Handle multi-frame reads**: a single `on_data` call may contain several
  complete frames plus a partial next one. Loop until you cannot make
  progress.
- **`on_flush` is your last chance**: return anything you still want
  captured before the session is recorded as closed.

If the script raises, the framer is logged as desynced and the cached
module is reloaded from disk on the next chunk — so you can edit and save
without restarting the proxy.
