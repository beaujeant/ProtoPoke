# Reverse-engineer an Unknown Protocol

Goal: starting from raw bytes flowing through a forwarder, end up with a
ProtoPoke protocol definition that decodes the messages into named,
typed fields.

The methodology below is the one used by Discoverer / Netzob / PRINCE
(automatic protocol reverse-engineering) adapted to ProtoPoke's MCP
tooling: **capture → frame → cluster → infer → validate → annotate →
actively confirm**. Skipping a step almost always leads to a definition
that decodes the easy frames and silently mis-decodes the rest.

This recipe assumes you already have a forwarder configured and at least
one session captured. If you do not, configure one with `add_forwarder`,
then `start_forwarder` and drive the client until you have a few dozen
frames in each direction.

## 0. Capture enough diversity

The single biggest mistake is reverse-engineering from too few frames.
You want **at least 30 frames per direction**, ideally exercising
multiple actions in the protocol (login, list, send, receive, error
path). Few frames → spurious "constant" bytes that are actually
variable.

```text
proxy_status                                  # confirm sessions exist
list_sessions                                 # pick a session_id
get_session_summary(session_id)               # frame counts per direction
```

If a direction has fewer than ~20 frames, go drive the client some more
before continuing. If you have many short sessions instead of one long
one, do the analysis per-session first (per-session state can confuse
the heuristics if conflated).

## 1. Get a coarse picture of the traffic

```text
get_frame_stats(session_id=session_id)        # buckets + per-offset stats
```

Read the output as follows:

- `size_distribution` — many distinct sizes ⇒ length-prefixed or
  delimited; one or two sizes dominate ⇒ fixed-format.
- `prefix_distributions` — a small number of dominant 1- or 2-byte
  prefixes is the strongest hint that the first byte(s) are an opcode /
  message-type field.
- `direction_counts` — strongly asymmetric counts usually mean the
  client polls (lots of small client messages) or the server pushes
  (lots of small server messages). Analyse each direction separately.

## 2. Decide on a framer

ProtoPoke's framer turns a stream of bytes into discrete `Frame`
objects. If the framer is wrong, every later step is wrong.

If frames look length-prefixed, ask ProtoPoke to find the length field
across the whole capture:

```text
find_length_fields(session_id=session_id)     # ranked length-field candidates
```

A candidate with the smallest plausible offset (usually 0–4) and a
constant ≈ 0 or equal to the header size is almost always the right
answer. Once identified, hot-swap the framer:

```text
list_framers                                  # see registered framers
update_forwarder_config(name, framer="length_prefix",
                        framer_options={"size": 2, "endianness": "big"})
```

For text-style protocols use `delimiter` with `\r\n` or `\n` (look at
`get_frames` output — if you see line breaks, that's your delimiter).
For anything stranger, write a custom framer using the `framers`
authoring guide (`protopoke://guides/framers`) and load it with
`set_framer`.

Re-drive the client, then confirm `get_frames` now returns one logical
message per frame (a sanity check is that the first byte of each frame
is small and from a short, repeating set — that's the opcode).

## 3. Cluster frames into message types (per direction)

```text
cluster_frames(session_id=session_id, direction="client_to_server")
cluster_frames(session_id=session_id, direction="server_to_client")
```

`cluster_frames` groups frames by `(first-N-byte prefix, length)`. Each
cluster is a candidate message type. Two heuristics for choosing
`prefix_len`:

- Start with `prefix_len=2`. Most binary protocols use a 1- or 2-byte
  opcode; clusters with the same length and only the first byte
  changing usually means the second byte is a sub-opcode/flag.
- If every prefix is unique, lower it to 1. If everything collapses
  into one cluster, raise it to 4.

Note clusters down: opcode hex, count, frame size. From here on, every
analysis tool can be scoped to one cluster using `byte_patterns`:

```text
{"byte_patterns": [{"offset": 0, "hex": "6d76"}], "size_bytes": 26}
```

## 4. For each cluster: infer field boundaries

For a same-size cluster, run all four structural analyses (each is
cheap and they catch different things):

```text
analyze_byte_ranges(session_id=session_id,
                    direction="client_to_server",
                    size_bytes=26,
                    byte_patterns=[{"offset": 0, "hex": "6d76"}])
entropy_map(session_id=session_id, ...same scoping...)
diff_frames_in_bucket(session_id=session_id, ...same scoping...)
find_length_fields(session_id=session_id,
                   byte_patterns=[{"offset": 0, "hex": "6d76"}])
```

Read the output looking for these patterns:

| Signal in output | Likely field |
|------------------|--------------|
| `change_rate == 0`, low entropy | Magic / opcode / padding (constant) |
| Low entropy, few distinct values | Enum / flags / version |
| `looks_like_length: true` | Length prefix (use the reported width + endianness) |
| `looks_like_counter: true` | Sequence number, timestamp, monotonic ID |
| `looks_like_ascii_run: true` | Embedded string (use `cstring` or `bytes` + length) |
| Entropy ≈ 8.0, change_rate ≈ 1.0 | Random ID, hash, ciphertext, nonce, payload |
| `candidate_types` includes float32 with `plausible: true` | Likely a float (coordinates, time deltas) |

Bytes that **change between frames** carry information; bytes that
**stay the same** are protocol structure. The single most reliable way
to draw field boundaries is to find runs of co-varying bytes.

For **mixed-size** clusters (same prefix, different sizes), the
above tools require same-size frames. Two cheap alternatives:

```text
align_frames(session_id=session_id,
             byte_patterns=[{"offset": 0, "hex": "6d76"}])
detect_tlv(session_id=session_id,
           byte_patterns=[{"offset": 0, "hex": "6d76"}],
           start_offsets=[2])           # skip the magic
```

`align_frames` runs a Needleman-Wunsch alignment against the first
frame — gap columns mark where one frame inserted/removed bytes,
``??`` columns mark variable bytes, ``xx`` columns mark constant
ones. `detect_tlv` tries every Type-Length-Value shape (T width
1/2, L width 1/2/4, BE/LE, length-includes-header) and reports the
ones that consume the whole frame as a record chain — the fastest
way to recognise TLV-shaped protocols (ASN.1, BACnet, Modbus, many
proprietary game protocols).

## 4b. Specialised field hunts

Generic stats catch most fields but miss the ones with well-defined
semantics. Run these three in parallel on the cluster:

```text
detect_checksums_crcs(session_id=session_id, ...same scoping...)
detect_timestamps(session_id=session_id, ...same scoping...)
detect_compression_encryption(session_id=session_id, ...same scoping...)
```

- **Checksums**: tries `sum8`, `xor8`, `sum16`, `fletcher16`,
  `crc16_ccitt`, `crc16_xmodem`, `crc32_ieee`, `adler32` against every
  candidate offset, in both endiannesses. A `coverage: 1.0` candidate
  is essentially proof that the field is a checksum of the rest of the
  frame — annotate it and `tamper` a byte-flip to confirm the server
  enforces it.
- **Timestamps**: finds uint32/uint64 fields whose value lies in a
  plausible unix-time / NTP / Windows-FILETIME range AND correlates with
  the frame's capture timestamp. The correlation breaks LE/BE ties.
- **Compression / encryption**: signature scan (gzip, zlib, lz4, zstd,
  PNG, ZIP, ELF, ASN.1, TLS records, …) plus high-entropy sliding
  windows. High-entropy regions inside an otherwise structured frame
  are usually nested ciphertext or compressed blobs — recurse into them
  with a separate framer / decoder.

Also scan for embedded human-readable content:

```text
extract_strings(session_id=session_id, min_length=4,
                byte_patterns=[{"offset": 0, "hex": "6d76"}])
```

Often the server name, app version, error message, or a username sits
in plain ASCII inside a frame and immediately tells you what the
message is for.

## 4c. Find recurring patterns regardless of offset

Many protocols sprinkle a 2-8 byte marker (frame trailer, record
separator, embedded magic) somewhere inside a variable-length payload.
Standard per-offset analysis can't see them; this one can:

```text
find_constant_byte_sequences(session_id=session_id,
                             direction="client_to_server",
                             min_length=2, max_length=8,
                             min_coverage=0.8)
```

Each reported n-gram comes with sample frame offsets — use those to
decide whether it's a fixed-position marker (just an unrecognised
opcode) or a true free-floating sentinel.

## 5. Spot relationships between fields

Some fields reference others (length-of, offset-of, count-of, hash-of).
Two cheap tools for surfacing those:

```text
offset_correlations(session_id=session_id,
                    offset_a=2, type_a="uint16_be",
                    offset_b=4, type_b="uint16_be",
                    byte_patterns=[{"offset": 0, "hex": "6d76"}])
```

`change_pairing` close to 1.0 = the two offsets change together. Use
this to find paired counters, x/y coordinate pairs, related flags, or a
length field that always grows when a payload offset moves.

For mixed-size clusters (same opcode, different sizes), `find_length_fields`
with a `byte_patterns` scope is the right call — it exploits the size
variation to identify which offset's value tracks frame length.

## 6. Compare two specific frames

When two frames in the same cluster differ in just a few bytes, see
exactly where:

```text
compare_frames(session_id=session_id,
               frame_id_a=<id_a>, frame_id_b=<id_b>)
```

The `differences` list coalesces differing byte runs into ranges with
an integer `delta_as_int` — extremely useful for spotting counters
(delta == 1 between consecutive frames), timestamps (delta ≈ elapsed
time), and session IDs (large random delta).

For paired analysis (client request vs server response), pick one of
each by `frame_id` and diff them — the shared bytes are usually the
transaction ID.

## 7. Sketch the first definition

Read the protocol-definition authoring guide for the YAML schema:

```text
list_authoring_guides
get_authoring_guide("protocol-definitions")   # or protopoke://guides/protocol-definitions
```

Build it incrementally in memory (every editing tool's effect is
visible to `decode_frames` on the next call — no reload step):

```text
create_protocol_definition(name="MyProto", endianness="big")

add_message_definition(message={
  "name": "LoginRequest",
  "match": {"type": "magic", "offset": 0, "value": [1]},
  "direction": "client_to_server",
  "fields": [
    {"name": "msg_type",     "type": "uint8"},
    {"name": "username_len", "type": "uint16"},
    {"name": "username",     "type": "bytes", "length": "username_len"}
  ]
})

# Tweak individual fields without rewriting the whole message:
add_field_to_message(message_name="LoginRequest",
                     field={"name": "flags", "type": "uint8"})
update_field_in_message(message_name="LoginRequest",
                        field_name="username_len",
                        field={"name": "username_len", "type": "uint16"})
```

Use `list_field_types` if you forget which field types are available.
For catch-all/passthrough messages set `match.type` to `"always"` and
put that message **last** in the list (matching is first-hit).

## 8. Validate against real frames

```text
decode_frames(session_id=session_id, direction="client_to_server")
decode_frames(session_id=session_id, direction="server_to_client")
```

For every frame check:

- It matched **one** message type (no `_no_match`).
- Field values look sensible (lengths match payload sizes, strings are
  printable, enums fall in range).
- The parser consumed the whole frame (no trailing bytes reported).

If something is wrong, edit the definition (`update_field_in_message`,
`update_message_definition`, `reorder_message_definition`,
`remove_message_definition`) and re-run `decode_frames`. Iterate until
the whole capture decodes cleanly. Watch out for two failure modes:

- **Over-matching**: a catch-all `match.type: always` placed above a
  specific magic-byte message will eat everything that comes after it.
  Use `reorder_message_definition` to fix.
- **Under-matching**: a magic value that's correct for some frames but
  doesn't hold for others — usually means you've conflated two message
  types. Split the definition.

## 9. Actively confirm with tamper

Decoding cleanly is necessary but not sufficient — the protocol might
just happen to be consistent with your hypothesis. To **confirm** a
field semantics, change it in flight and observe the server's
reaction:

```text
tamper_toggle(enabled=True)
add_intercept_rule(label="catch_login", pattern="01",
                   action="intercept", direction="client_to_server")
# … drive the client to send a login …
list_intercepted
tamper_modify_field_and_forward(unit_id=<unit>,
                                field_edits={"username": "admin"})
```

Three useful "confirmation" probes:

- Flip a hypothesised length field by ±1 — the server should reject /
  truncate / over-read; this proves it's a length.
- Replace a string field with something obviously wrong (`"x"*1000`) —
  the server's error message often names the field.
- XOR a putative checksum byte and verify the server rejects the
  frame — this proves the field guards integrity.

This step is what separates a working protocol definition from a
guessed one.

## 10. Persist

```text
save_protocol_to_file(path="my_proto.yaml")
```

From now on `set_protocol_file("my_proto.yaml")` brings the decoder
back, and every captured frame on every forwarder using this protocol
will decode with named fields visible in `get_frames`,
`tamper_decode_pending`, `replay_with_field_edits`, and the Traffic tab.

## Cross-references

- Authoring guide: `protopoke://guides/protocol-definitions`
- Authoring guide: `protopoke://guides/framers`
- Recipe: `protopoke://recipes/validate-with-tamper`
- Recipe: `protopoke://recipes/map-state-machine`
- Tool index: `protopoke://tools`
