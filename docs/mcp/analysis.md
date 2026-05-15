---
title: "Protocol Reversing over MCP"
---

ProtoPoke's analysis tools let an AI assistant reverse-engineer a binary
protocol end-to-end through MCP — no need to dump frames to disk, no local
Python scripts, no context-switching out of the AI client. Every helper is
protocol-agnostic: no hard-coded magic bytes, no domain-specific value
ranges.

This page walks through a typical workflow. The example assumes you've
already captured some traffic in session `S`.

## The workflow

```
cluster_frames   →   find packet-type buckets
   ↓
analyze_byte_ranges + find_length_fields   →   structure of one bucket
   ↓
decode_field (with deduplicate)   →   verify each field's interpretation
   ↓
add_message_definition + add_field_to_message   →   write it back
   ↓
save_protocol_to_file   →   persistent .yaml / .json
```

## 1. Discover packet types

Most binary protocols multiplex several message types onto one connection.
`cluster_frames` buckets frames by `(first-N-byte prefix, length)`:

```
cluster_frames(session_id=S, prefix_len=2)
→ {
    "clusters": [
      {"prefix_hex": "6d76", "size_bytes": 26, "count": 412, ...},
      {"prefix_hex": "6862", "size_bytes": 3,  "count":  88, ...},
      ...
    ]
  }
```

Each cluster is a candidate packet type. `get_frame_stats` returns the same
buckets together with per-offset change-rate and Shannon entropy for every
bucket with ≥3 frames — useful for spotting which offsets actually carry
information.

## 2. Scope to one bucket

Every analysis tool accepts the same scoping parameters so you can focus on
one packet type at a time:

| Parameter | Purpose |
|---|---|
| `direction` | `"client_to_server"` or `"server_to_client"` |
| `size_bytes` | Restrict to frames of exactly this length |
| `byte_patterns` | List of `{offset, hex}` — every pattern must match its offset |

Example: scope to "mv" (0x6d 0x76) client→server frames of 26 bytes:

```
{
  "direction": "client_to_server",
  "size_bytes": 26,
  "byte_patterns": [{"offset": 0, "hex": "6d76"}]
}
```

## 3. Find structure

### `analyze_byte_ranges`

For each contiguous run of varying offsets, scores candidate types and flags
generic patterns:

- `candidate_types`: every plausible interpretation (uint/int LE/BE at 1/2/4/8
  bytes, plus float32 LE/BE for 4-byte widths) with min/max/distinct counts.
- `looks_like_length`: `True` when the value equals `frame_size - C` for the
  same `C` across every frame.
- `looks_like_counter`: values are (mostly) monotonic over time.
- `looks_like_ascii_run`: ≥80% printable ASCII bytes.

### `find_length_fields`

Works across **mixed-size** frames — most generic length-prefix detection
needs frames of different sizes to disambiguate. Reports every
`(offset, width, byteorder)` combination where the integer value equals
`len(frame) - C` for the same `C` across every frame. Call this on the
whole session (no `size_bytes` filter) to find the length prefix that
explains the size variation.

### `diff_frames_in_bucket`

Column-by-column diff matrix across same-size frames, sorted by most-varying
offset first. Each column is one byte per frame in capture order, hex-
concatenated — extremely token-cheap.

### `entropy_map`

Per-offset Shannon entropy across a same-size bucket. Constants → 0,
encrypted/compressed regions → near 8, structured fields somewhere between.

## 4. Verify a guess

`decode_field` parses `raw_bytes[offset:offset+size]` as a given type across
every selected frame. Use `list_field_types` to see the full type list
(`uint16_le`, `float32_be`, `int8`, `ascii`, `cstring`, …).

```
decode_field(
  session_id=S, offset=2, size=4, type="float32_le",
  size_bytes=26, byte_patterns=[{"offset": 0, "hex": "6d76"}],
  deduplicate=True,
)
```

`deduplicate=True` is the single highest-leverage primitive in the analysis
toolkit: it only emits a row when the decoded value **changes**, which
surfaces state transitions (coordinate updates, counters, flag changes) in a
long capture without dumping every frame.

`offset_correlations` checks whether two offsets co-vary (Pearson `r` and
`change_pairing`) — useful for detecting paired counters or related fields.

## 5. Compare two specific frames

When you need to inspect a single transition, `compare_frames` gives a
byte-level diff between two frames:

- coalesced list of differing byte ranges (with offsets and integer delta
  where applicable)
- common prefix / suffix lengths
- 16-byte-row side-by-side hex view

## 6. Annotate the protocol

Once you've figured out the structure, persist it by editing the active
`ProtocolDefinition` directly. The new fields take effect immediately —
`decode_frames`, the TUI's parsed-tree view, and
`tamper_modify_field_and_forward` all use the updated definition on the next
call.

```
create_protocol_definition(name="MyGame", endianness="little")

add_message_definition({
  "name": "PositionUpdate",
  "match": {"type": "magic", "offset": 0, "value": [0x6d, 0x76]},
  "direction": "client_to_server",
  "fields": [
    {"name": "opcode", "type": "bytes", "length": 2},
    {"name": "x",      "type": "float32"},
    {"name": "y",      "type": "float32"},
    {"name": "z",      "type": "float32"}
  ]
})

# Add or replace individual fields incrementally:
add_field_to_message("PositionUpdate", {"name": "yaw", "type": "float32"})
update_field_in_message("PositionUpdate", "opcode",
  {"name": "opcode", "type": "uint16"})
```

Then commit to disk:

```
save_protocol_to_file("./protocols/mygame.yaml")
```

The resulting file is a regular YAML/JSON protocol definition — load it next
session with `set_protocol_file` (or via the Config tab in the TUI).

## Reference

- All analysis tools: [Tool Reference → Analysis](/mcp/tools#analysis)
- All editing tools: [Tool Reference → Protocol Definition Editing](/mcp/tools#protocol-definition-editing)
- Definition schema: [Protocol Definitions](/reference/protocol-definitions)
