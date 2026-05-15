# Authoring a Protocol Definition

A protocol definition is a YAML (or JSON) file that tells ProtoPoke how to
decode raw frames into named, typed fields. It powers Wireshark-style
display, intercept field editing, and Forge variable extraction — without
writing any Python.

## File Format

```yaml
protocol:
  name: "MyProto"
  version: "1.0"           # optional
  endianness: big          # big | little

  messages:
    - name: "LoginRequest"
      match:
        type: magic
        offset: 0
        value: "0x01"
      fields:
        - { name: opcode,       type: uint8,  display: hex }
        - { name: username_len, type: uint16 }
        - { name: username,     type: string, length: "{username_len}" }

    - name: "GenericPacket"
      match:
        type: always
      fields:
        - { name: data, type: bytes, length: -1, display: hex }
```

The parser evaluates `messages` **top-to-bottom** and uses the first match,
so put specific rules before catch-all rules. The last entry is usually a
`type: always` catch-all so unknown frames are still rendered.

## Loading a Definition

```python
# Per-forwarder, loaded when the forwarder starts
fwd = ForwarderConfig(
    ...,
    protocol_definition_path="myproto.yaml",
)

# Hot-swap at runtime
api.set_protocol_file("myproto.yaml")

# Or load from an in-memory dict
api.set_protocol_dict({
    "name": "MyProto",
    "endianness": "big",
    "messages": [...],
})
```

Via MCP:

```
set_protocol_file(path="/path/to/myproto.yaml")
```

## Match Strategies

### `magic` — Match Bytes at a Fixed Offset

The most common strategy. Identify packets by a fixed opcode or magic.

```yaml
match:
  type: magic
  offset: 0
  value: "0x01"           # single byte

# multi-byte sequence
match:
  type: magic
  offset: 0
  value: [0xDE, 0xAD]
```

Accepted value formats: `"0x10"`, `16`, `[0x10]`, `"0x10 0x00"`,
`[0x10, 0x00]`.

### `sequence` — Match by Stream Position

Match frames by their position in the stream (useful for handshakes /
banners that always appear at a known index).

```yaml
match:
  type: sequence
  direction: server_to_client   # which direction to count
  index: 0                      # 0-based position
```

### `always` — Catch-All

Always matches. Use as the **last** entry to catch anything not handled by
earlier definitions.

```yaml
match:
  type: always
```

## Field Types

All fields share these common keys:

| Key       | Required | Description                                                          |
|-----------|----------|----------------------------------------------------------------------|
| `name`    | yes      | Unique identifier; referenced in length / count expressions          |
| `type`    | yes      | Field type (see below)                                               |
| `display` | no       | Rendering hint: `auto`, `hex`, `ascii`, `decimal`, `enum`            |

### Integers

```yaml
- name: opcode
  type: uint8       # uint8 | uint16 | uint32 | uint64 | int8 | int16 | int32 | int64
  display: hex
```

Sizes: 1, 2, 4, or 8 bytes. Endianness follows the top-level `endianness`
setting.

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

The integer width is inferred from the highest bit index (rounded up to
the nearest byte).

### Array

Counted sequence of identical sub-structures:

```yaml
- name: records
  type: array
  array:
    count: "{record_count}"
    item:
      - { name: id,       type: uint32 }
      - { name: name_len, type: uint8 }
      - { name: name,     type: string, length: "{name_len}" }
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

| Format            | Example                  | Meaning                                |
|-------------------|--------------------------|----------------------------------------|
| Fixed integer     | `4`                      | Always 4 bytes                         |
| Field reference   | `"{payload_len}"`        | Value of a previously parsed field     |
| Arithmetic        | `"{total_length - 5}"`   | Computed from field values             |
| Rest of frame     | `-1`                     | Consume all remaining bytes            |
| Null terminated   | `null_terminated: true`  | Scan until `\x00`                      |

Expressions support `+`, `-`, `*`, `//` and builtins `min()`, `max()`,
`abs()`, `int()`. Field names in `{}` are substituted by their parsed
integer value. Evaluation is sandboxed.

## Iterative Authoring Workflow

Reverse engineering a protocol is incremental. Start minimal and expand.

**Pass 1 — split opcode from payload:**

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
        - { name: rest,   type: bytes, length: -1, display: hex }
```

**Pass 2 — add a specific message type before the catch-all:**

```yaml
- name: "LoginRequest"
  direction: client_to_server
  match:
    type: magic
    offset: 0
    value: "0x01"
  fields:
    - { name: opcode,       type: uint8 }
    - { name: username_len, type: uint16 }
    - { name: username,     type: string, length: "{username_len}" }
    - { name: password_len, type: uint16 }
    - { name: password,     type: bytes,  length: "{password_len}", display: hex }
```

**Pass 3** — keep adding message types until no `rest` placeholders remain.

## Authoring Tips

- **Order matters**: the parser uses the *first* matching message
  definition. Put the most specific matches first and a `type: always`
  catch-all last.
- **Validate as you go**: load with `api.set_protocol_file(...)` and watch
  the Traffic tab to confirm each frame decodes as expected.
- **Use the analysis MCP tools** (`get_frame_stats`, `cluster_frames`,
  `entropy_map`, `analyze_byte_ranges`, `find_length_fields`) to discover
  structural patterns before writing definitions by hand.
- **Edit live via MCP**: `add_message_definition`,
  `add_field_to_message`, etc. let you build a definition incrementally
  and save it with `save_protocol_to_file`.
- **Examples shipped with the repo**: `examples/protocols/chat.proto.yaml`
  (all field types), `examples/protocols/dns.proto.yaml` (real protocol).
