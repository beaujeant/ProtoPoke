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
cluster_frames + detect_periodic_streams   →   find packet-type buckets & streams
   ↓
analyze_byte_ranges + find_length_fields + bruteforce_numeric_layout   →   structure of one bucket
   ↓
analyze_field_correlation / decode_field (with deduplicate)   →   verify each field's interpretation
   ↓
add_finding (record what you confirmed)   →   knowledge base
   ↓
Compose YAML in chat   →   operator saves & loads it
```

ProtoPoke deliberately does **not** expose any MCP tool that writes a
protocol definition.  The AI's job is to gather evidence, record what
it learns in the knowledge base, and — when the structure is stable
— hand the operator a YAML definition to load.

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

`detect_periodic_streams` groups by the same `(prefix, size)` key and reports,
per bucket, the mean / standard deviation / coefficient of variation of the
inter-arrival times and an `is_periodic` flag. Heartbeats, position pings, and
keepalives stand out immediately — and a steady stream is often the easiest
packet type to start reverse-engineering.

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

### `bruteforce_numeric_layout`

The fastest first pass on a fixed-size packet type. It samples frames from one
size bucket (the dominant size by default, or `size_bytes` if given) and scores
**every numeric encoding at every offset** on three protocol-agnostic signals:
float validity (no NaN/Inf), high-byte stability (real coordinates and counters
don't span the full type range, so the most-significant byte has low entropy),
and smoothness / monotonicity between temporally adjacent frames. The top
candidates are exactly what a human guesses by hand — without writing a script.

```
bruteforce_numeric_layout(session_id=S, size_bytes=26, direction="client_to_server")
→ {
    "size_bytes": 26, "sample_size": 200,
    "candidates": [
      {"offset": 2, "encoding": "f32_le", "score": 0.91, "smoothness": 0.95, ...},
      ...
    ]
  }
```

!!! note

    These field tools use **compact encoding names** — `u8`, `i8`, `u16_le`,
    `u16_be`, `i16_le`, `i16_be`, `u32_le`, `u32_be`, `i32_le`, `i32_be`,
    `f32_le`, `f32_be`, `f64_le`, `f64_be` — distinct from the verbose
    `decode_field` type list (`uint16_le`, `float32_be`, …). Any `byte_length`
    argument must match the encoding width.

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

`analyze_field_correlation` is the compact-encoding counterpart to
`decode_field`: it returns a clean time series — one row per frame with
`frame_id`, `timestamp`, `sequence_number`, and the decoded `value` — for a
single `(byte_offset, byte_length, encoding)` field. It saves writing a
throwaway script just to plot how one candidate field evolves.

`group_by_field_value` buckets frames by the concatenated value across one or
more `(offset, length)` ranges and returns `{key_hex: [frame_ids]}` plus
per-bucket counts. Where `get_frame_stats` reports per-offset entropy, this
shows multi-offset **co-occurrence** — the join distribution of, say, two
input-axis bytes or a pair of flag fields.

### `bisect_field_meaning` — confirm by observation

Inference can be confirmed by experiment. Given a live forge session (open one
with `open_forge_session`), a base frame, and a `(byte_offset, byte_length,
encoding)` triple, `bisect_field_meaning` sweeps the field across a list (or
`{start, stop, step}` range) of candidate values, replays the frame for each,
and returns `{candidate_value: response_bytes_hex}`. It's the natural
counterpart to `replay_with_field_edits`: instead of reasoning about what a
field means, you watch how the server responds when you change it.

## 5. Compare two specific frames

When you need to inspect a single transition, `compare_frames` gives a
byte-level diff between two frames:

- coalesced list of differing byte ranges (with offsets and integer delta
  where applicable)
- common prefix / suffix lengths
- 16-byte-row side-by-side hex view (each row has `a_hex` and `differs`;
  `b_hex` appears only on rows that differ — when absent the row is identical,
  so `b_hex == a_hex`)

`diff_frames` is the field-aware variant: it lists every differing byte
(offset + both hex values) and, given a list of `(offset, length, encoding)`
field declarations, also reports the **decoded delta** in each declared field —
the direct answer to "what changed between this frame and the next?"

### `find_constant_byte_sequences`

Finds byte n-grams that appear in at least `min_coverage` of the selected
frames regardless of offset. Surfaces magic markers, version stamps, and
trailers that constant-offset stats miss. Strict substrings of a longer hit
with the same coverage are suppressed automatically.

### `align_frames`

Needleman-Wunsch global alignment of mixed-size frames against the first
selected frame. Returns the aligned rows as hex strings (with `--` for
gaps), a consensus row (`xx` where every row agrees, `??` where rows
differ, `--` for gaps), and the coalesced variable regions. Use this for
clusters that share structure but have different lengths.

### `extract_strings`

`strings(1)` for captured frames — every printable-ASCII run of length ≥
`min_length` with its frame ID and offset. Set `include_utf16_le=True`
for Windows-style strings (printable bytes interleaved with NULs).

### `detect_tlv`

Tries every Type-Length-Value layout (`type_width` ∈ {1, 2},
`length_width` ∈ {1, 2, 4}, BE/LE, length-includes-header / value-only)
at the given `start_offsets` and reports shapes that consume entire
frames as a chain of records. Each candidate also reports the most
common type values seen — often the actual opcode / tag enumeration.

### `detect_checksums_crcs`

Tries `sum8`, `xor8`, `sum16`, `fletcher16`, `crc16_ccitt`,
`crc16_xmodem`, `crc32_ieee`, `adler32` against every plausible offset
in every frame. For multi-byte algorithms both endiannesses are tried.
The algorithm is computed over the frame's bytes *excluding* the
candidate field, so a match means the field really is a checksum of
the rest.

### `detect_timestamps`

For every `(offset, width ∈ {4, 8}, byteorder)` candidate, checks how
many frames' decoded value falls in each known epoch range
(`unix_seconds`, `unix_milliseconds`, `ntp_seconds`,
`windows_filetime`). Reports the Pearson correlation between the
decoded value and the frame's capture timestamp — use the correlation
to disambiguate LE vs BE.

### `detect_compression_encryption`

Per-frame: scans for known magic signatures (gzip, zlib, lz4, zstd,
ZIP, 7z, RAR, PNG, JPEG, GIF, PDF, ELF, PE, ASN.1 SEQUENCE, TLS
handshake records, SSH banners, …) and reports sliding-window
high-entropy regions (Shannon entropy ≥ `high_entropy_min` over
`window_size` bytes — default 128 bytes / 6.5 bits, which catches
compressed and encrypted payloads while ignoring structured binary).

### `echo_detection`

Walks the session in capture order. For each source frame and width
(default `[2, 4, 8]`), checks whether any non-trivial value sent at
`src_offset` reappears at a fixed `dst_offset` in the next
`max_distance` frames in the opposite direction. Triples
`(src_offset, dst_offset, width)` with at least `min_coverage` of
source frames echoed are reported — the classic transaction-ID /
session-token pattern.

### `export_session_csv`

When you want to plot or crunch a session in an external notebook,
`export_session_csv` flattens it in one call: given a list of declared fields
(`name`, `byte_offset`, `byte_length`, `encoding`, and an optional
`message_filter` byte pattern), it returns a CSV string with one row per frame
and one column per field, plus `frame_id`, `timestamp`, `sequence_number`,
`direction`, and `size`. Cells are blank where a frame is too short or fails
its `message_filter`.

## 6. Record findings in the knowledge base

Every confirmed (or ruled-out) hypothesis goes into the knowledge
base so the next AI session does not have to re-derive it.  Findings
are scoped (protocol / message / field / byte range / forwarder) and
carry a status (`hypothesis` / `confirmed` / `ruled_out` /
`needs_review`) and confidence (`low` / `medium` / `high`).

```
add_finding(
    title="bytes 0-1 of PositionUpdate are the magic 'mv'",
    status="confirmed", confidence="high",
    message_name="PositionUpdate",
    byte_offset=0, byte_length=2,
    evidence_frame_ids=[...],
    tags=["magic", "opcode"],
)
```

See the [Knowledge Base guide](knowledge.md) for the full schema.

## 7. Hand the operator a protocol definition

When the structure is stable, compose the YAML in chat and ask the
operator to save it (e.g. `./protocols/mygame.yaml`) and load it
(via the Config tab in the TUI, or by pointing a
`ForwarderConfig.protocol_definition_path` at it).  The MCP server
has no write path for protocol definitions — keeping that authority
with the operator means a single review gate before any change to
how frames are decoded.

```yaml
protocol:
  name: "MyGame"
  endianness: little
  messages:
    - name: PositionUpdate
      direction: client_to_server
      match: { type: magic, offset: 0, value: [0x6d, 0x76] }
      fields:
        - { name: opcode, type: bytes, length: 2 }
        - { name: x,      type: float32 }
        - { name: y,      type: float32 }
        - { name: z,      type: float32 }
        - { name: yaw,    type: float32 }
```

Use `get_protocol_definition_schema` for the full spec (field types,
match strategies, length expressions, bitfields, TLV sequences).
After the operator loads the YAML, call `get_protocol_definition` to
confirm the parser accepted it, then call `decode_frames` to verify
each frame decodes cleanly.

## Reference

- All analysis tools: [Tool Reference → Analysis](tools.md#analysis)
- Knowledge base: [Knowledge Base](knowledge.md)
- Definition schema: [Protocol Definitions](../reference/protocol-definitions.md)
