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

## 4. Budget-aware analysis ladder

ProtoPoke gives you 10+ analytical tools.  Firing every one on every
cluster wastes the AI's context window and your own time. Use this
ladder: cheap broad tools first, expensive narrow tools only when
something is still mysterious. Two rules carry most of the savings:

- **Always scope** every analysis call with `byte_patterns` (and
  `size_bytes` for same-size tools).  An unscoped call on a large
  capture returns the union of every packet type, which is both
  noisier and many times larger.
- **Stop when you have the answer.**  If `find_length_fields` returns
  one `coverage: 1.0` candidate, you don't need `detect_tlv` for that
  cluster.  If a string popped out of `extract_strings` that explains
  a region, you don't need `analyze_byte_ranges` on it.  Move on to
  the next unknown.

Cost / value cheat-sheet (rough output size, expected use frequency):

| Tool | Cost | Scope | Run … |
|------|------|-------|-------|
| `find_length_fields` | small | whole session, no size filter | **once per direction**, very early |
| `extract_strings` | small unless many frames | session OR cluster | once early; re-run scoped if a cluster has strings |
| `find_constant_byte_sequences` | small (capped at 50 results) | session OR cluster | once early per direction |
| `analyze_byte_ranges` | small | one same-size cluster | per cluster, once |
| `entropy_map` | tiny (one float per offset) | one same-size cluster | per cluster, once |
| `diff_frames_in_bucket` | small (top 64 varying offsets) | one same-size cluster | only if `analyze_byte_ranges` left ambiguity |
| `detect_checksums_crcs` | small candidate list | one cluster | only when bytes look like noise but might be a guard |
| `detect_timestamps` | small candidate list | one cluster | only when a 4- or 8-byte field looks counter-like |
| `detect_tlv` | small candidate list | one cluster of mixed sizes | only when the size distribution suggests record chains |
| `align_frames` | **moderate** (≤ 20 rows × ≤ 512 hex pairs) | one mixed-size cluster, small sample | only when `analyze_byte_ranges` cannot apply |
| `detect_compression_encryption` | moderate (per-frame findings) | one cluster, ≤ 20 frames | only when a region's entropy is suspiciously high |
| `offset_correlations` | small | one cluster | only to confirm a specific pairing hypothesis |
| `compare_frames` | small | two specific frames | for spot inspections, not bulk analysis |

What to actually run for a *first pass*:

1. **`find_length_fields`** + **`extract_strings`** +
   **`find_constant_byte_sequences`** on the whole session, per
   direction.  These three together identify the framing, every
   readable ASCII region, and every recurring marker before you
   look at a single cluster.
2. For the **2–3 largest clusters**: `analyze_byte_ranges` +
   `entropy_map`. That handles the majority of fixed-size message
   types.
3. Escalate **only when needed**:
   - Cluster has mixed sizes: `align_frames` (capped sample) or
     `detect_tlv`.
   - Cluster has a high-entropy tail or a 4-byte field whose
     `change_rate ≈ 1.0`: `detect_compression_encryption`.
   - Cluster has a noisy-looking 1/2/4-byte field at the very end or
     very start: `detect_checksums_crcs`.
   - Cluster has a monotonic 4- or 8-byte field: `detect_timestamps`.
4. For specific pairings only: `offset_correlations` and
   `compare_frames`.

The rest of this section explains each step.

## 4a. Session-level sweep (run once per direction)

Three cheap, broad tools that punch above their weight:

```text
find_length_fields(session_id=session_id,
                   direction="client_to_server")
extract_strings(session_id=session_id,
                direction="client_to_server",
                min_length=4, max_per_frame=20)
find_constant_byte_sequences(session_id=session_id,
                             direction="client_to_server",
                             min_length=2, max_length=6,
                             min_coverage=0.8, max_results=30)
```

Why these three first:

- `find_length_fields` is the **only** length-detector that exploits
  size variation, so it must see the unfiltered capture.  Run it
  before you bucket anything.
- `extract_strings` immediately surfaces version banners, usernames,
  error messages, and embedded paths — these often name the protocol
  outright.
- `find_constant_byte_sequences` catches free-floating magic markers
  and trailers that constant-offset stats miss.  Default
  `min_coverage=0.8` keeps the output to the genuinely recurring ones;
  `max_length=6` keeps the candidate space small.

Repeat for `server_to_client`.  If the output is short, you've got
your high-value answers for cheap; if it's long, raise `min_coverage`
to 0.95 to skim only the strongest hits.

## 4b. Per-cluster inference (same-size frames)

For each of the **2–3 largest** clusters (don't run this on every
cluster — most of the long tail are echoes of the patterns the big
clusters reveal), run:

```text
analyze_byte_ranges(session_id=session_id,
                    direction="client_to_server",
                    size_bytes=26,
                    byte_patterns=[{"offset": 0, "hex": "6d76"}])
entropy_map(session_id=session_id, ...same scoping...)
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
**stay the same** are protocol structure.

Only run `diff_frames_in_bucket` as a **follow-up** when
`analyze_byte_ranges` says many offsets vary but you can't tell which
move together — diff gives you the per-frame columns directly. Skip
it otherwise.

## 4c. Per-cluster inference (mixed-size frames)

For clusters where the same prefix appears at multiple sizes, the
same-size tools above don't apply. Pick **one** of:

```text
# Cheaper: report TLV shapes that match the cluster:
detect_tlv(session_id=session_id,
           byte_patterns=[{"offset": 0, "hex": "6d76"}],
           start_offsets=[2])                # skip the magic

# More expensive but more informative when TLV doesn't apply:
align_frames(session_id=session_id,
             byte_patterns=[{"offset": 0, "hex": "6d76"}],
             max_frames=10, max_frame_size=128)
```

Try `detect_tlv` first — output is a small candidate list and a
matching shape essentially solves the cluster. Only fall back to
`align_frames` when no TLV shape covers the cluster, and **cap the
sample**: 10 frames at 128 bytes each is usually enough to see the
structure and keeps the response under ~3 KB.

## 4d. Specialised hunts (run only when relevant)

These three are cheap per-call but have specific triggers — don't fire
them on every cluster:

- **`detect_checksums_crcs`** — run when there's a 1/2/4-byte field at
  the very start or end of the cluster that looks like noise
  (entropy > 7, change_rate ≈ 1.0) and you suspect integrity protection.
  A `coverage: 1.0` candidate is essentially proof; confirm with a
  `tamper` byte-flip per the `validate-with-tamper` recipe.
- **`detect_timestamps`** — run when a 4- or 8-byte field is monotonic
  (`looks_like_counter: true` in `analyze_byte_ranges`). The reported
  `pearson_r_with_capture_time` disambiguates LE vs BE.
- **`detect_compression_encryption`** — run when a high-entropy region
  (`entropy_bits > 7`) appears inside an otherwise structured frame.
  This is the only tool whose output can grow with frame count —
  scope tightly and keep `max_per_frame ≤ 5` to bound size.

```text
detect_checksums_crcs(session_id=session_id, ...scoping...)
detect_timestamps(session_id=session_id, ...scoping...)
detect_compression_encryption(session_id=session_id, ...scoping...,
                              max_per_frame=4)
```

If a cluster has no candidate field matching any of these triggers,
skip the call entirely.

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
