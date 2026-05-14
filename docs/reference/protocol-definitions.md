---
title: "Protocol Definitions"
---

ProtoPoke can decode raw frames into named, typed fields using a YAML or JSON protocol definition file. This gives you Wireshark-style display with per-field colour-coded hex dumps and a nested field tree — without writing any code.

## Overview

A protocol definition describes:

- The **endianness** of integer fields (big or little)
- A list of **message types**, each with:
    - A **match rule** to identify which frames belong to this type
    - A list of **fields** that describe the byte layout

The parser evaluates message definitions **top-to-bottom** and uses the first match, so put specific rules before catch-all rules.

## File Format

Create a `.yaml` or `.json` file:

```yaml
protocol:
  name: "MyProto"
  version: "1.0"          # optional
  endianness: big          # big or little

  messages:
    - name: "LoginRequest"
      match:
        type: magic
        offset: 0
        value: "0x01"
      fields:
        - { name: opcode, type: uint8, display: hex }
        - { name: username_len, type: uint16 }
        - { name: username, type: string, length: "{username_len}" }

    - name: "GenericPacket"
      match:
        type: always
      fields:
        - { name: data, type: bytes, length: -1, display: hex }
```

## Loading a Definition

<Tabs>
  <Tab title="TUI">
    Config tab → set **Protocol Definition File** to the path of your `.yaml` file → click **Apply**.
  </Tab>
  <Tab title="Python API">
    ```python
    # Via config (loaded on start)
    fwd = ForwarderConfig(
        ...,
        protocol_definition_path="myproto.yaml",
    )

    # Hot-swap at runtime
    api.set_protocol_file("myproto.yaml")

    # Load from a dict
    api.set_protocol_dict({
        "name": "MyProto",
        "endianness": "big",
        "messages": [...],
    })
    ```
  </Tab>
  <Tab title="MCP">
    ```
    set_protocol_file(path="/path/to/myproto.yaml")
    ```
  </Tab>
</Tabs>

## Match Strategies

Three strategies identify which message definition applies to a frame.

### `magic` — Match Bytes at a Fixed Offset

The most common strategy. Identify packets by a fixed opcode or magic sequence:

```yaml
match:
  type: magic
  offset: 0                    # byte offset from frame start
  value: "0x01"                # single byte
```

```yaml
match:
  type: magic
  offset: 0
  value: [0xDE, 0xAD]         # multi-byte sequence
```

Accepted value formats: `"0x10"`, `16`, `[0x10]`, `"0x10 0x00"`, `[0x10, 0x00]`.

### `sequence` — Match by Stream Position

Match frames by their position in the stream (useful for handshakes/banners):

```yaml
match:
  type: sequence
  direction: server_to_client  # which direction to count
  index: 0                     # 0-based position
```

### `always` — Catch-All

Always matches. Use as the **last** entry to catch anything not handled by earlier definitions:

```yaml
match:
  type: always
```

## Field Types

All fields share these common keys:

| Key | Required | Description |
|-----|----------|-------------|
| `name` | yes | Unique identifier; referenced in length expressions |
| `type` | yes | Field type (see below) |
| `display` | no | Rendering hint: `auto`, `hex`, `ascii`, `decimal`, `enum` |

### Integers

```yaml
- name: opcode
  type: uint8       # uint8 | uint16 | uint32 | uint64 | int8 | int16 | int32 | int64
  display: hex
```

Sizes: 1, 2, 4, or 8 bytes. Endianness follows the top-level `endianness` setting.

### Floats

```yaml
- name: temperature
  type: float32     # float32 (4 bytes) | float64 (8 bytes)
```

### Bytes

Raw byte sequence with a required length:

```yaml
- name: payload
  type: bytes
  length: "{payload_len}"
  display: hex
```

### String

Decoded text:

```yaml
- name: username
  type: string
  length: "{username_len}"    # length in bytes
  encoding: utf8              # utf8 (default) | ascii | utf16
```

Null-terminated variant:

```yaml
- name: hostname
  type: string
  null_terminated: true
  encoding: ascii
```

### Padding

Skip alignment or reserved bytes (not parsed or displayed):

```yaml
- name: reserved
  type: padding
  length: 3
```

### Enum

Any integer field can carry named values:

```yaml
- name: status
  type: uint8
  display: enum
  enum:
    0x00: "Success"
    0x01: "Not Found"
    0xFF: "Unknown Error"
```

### Bitfield

Integer decoded as individually named bits:

```yaml
- name: flags
  type: bitfield
  bits:
    0: syn           # bit 0 (LSB)
    1: ack
    2: fin
    7: urgent
```

The integer width is inferred from the highest bit index (rounds up to the nearest byte).

### Array

Counted sequence of identical sub-structures:

```yaml
- name: records
  type: array
  array:
    count: "{record_count}"
    item:
      - { name: id, type: uint32 }
      - { name: name_len, type: uint8 }
      - { name: name, type: string, length: "{name_len}" }
```

### TLV Sequence

Stream of Type-Length-Value triples:

```yaml
- name: attributes
  type: tlv_sequence
  length: "{total_length - 5}"
  tlv:
    type_size: 2
    length_size: 2
    endianness: big
    tags:
      0x0001:
        name: "UserID"
        value_type: uint32
      0x0002:
        name: "Username"
        value_type: string
        encoding: utf8
```

## Length Expressions

The `length` and `count` keys accept several formats:

| Format | Example | Meaning |
|--------|---------|---------|
| Fixed integer | `4` | Always 4 bytes |
| Field reference | `"{payload_len}"` | Value of a previously parsed field |
| Arithmetic | `"{total_length - 5}"` | Computed from field values |
| Rest of frame | `-1` | Consume all remaining bytes |
| Null terminated | `null_terminated: true` | Scan until `\x00` |

Expressions support `+`, `-`, `*`, `//` and builtins `min()`, `max()`, `abs()`, `int()`. Field names in `{}` are substituted by their parsed integer value. Evaluation is sandboxed.

## Working with Parsed Messages

```python
# Get parsed message from intercepted frame
unit, msg = await api.get_next_intercepted_parsed()

print(msg.message_type)            # e.g. "LoginRequest"
print(msg.protocol_name)           # e.g. "MyProto"

# Access a field by name
f = msg.field_by_name("username")
print(f.value)                     # Python value
print(f.display_value)             # Rendered string
print(f.offset)                    # Byte offset in frame
print(f.size)                      # Bytes consumed

# All fields as a flat dict
print(msg.as_dict())               # {"opcode": 1, "username": "admin", ...}

# Forward with field edit (length fields auto-recomputed)
api.modify_field_and_forward(unit.id, {"username": "hacker"})
```

## Iterative Definition Building

Reverse engineering a protocol is incremental. Start minimal and expand:

**Pass 1 — Split opcode from payload:**

```yaml
protocol:
  name: "Unknown"
  endianness: big
  messages:
    - name: "Packet"
      match:
        type: always
      fields:
        - { name: opcode, type: uint8, display: hex }
        - { name: rest, type: bytes, length: -1, display: hex }
```

**Pass 2 — Add a specific message type:**

```yaml
    - name: "LoginRequest"
      direction: client_to_server
      match:
        type: magic
        offset: 0
        value: "0x01"
      fields:
        - { name: opcode, type: uint8 }
        - { name: username_len, type: uint16 }
        - { name: username, type: string, length: "{username_len}" }
        - { name: password_len, type: uint16 }
        - { name: password, type: bytes, length: "{password_len}", display: hex }

    - name: "Packet"
      match:
        type: always
      fields:
        - { name: opcode, type: uint8, display: hex }
        - { name: rest, type: bytes, length: -1, display: hex }
```

**Pass 3** — continue adding message types until no `rest` placeholders remain.

## Examples

See the included example protocol definitions:

- `examples/protocols/chat.proto.yaml` — a fictional chat protocol covering all field types (enum, bitfield, array, TLV)
- `examples/protocols/dns.proto.yaml` — DNS protocol definition
