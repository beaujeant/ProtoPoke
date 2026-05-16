# Reverse-engineer an Unknown Protocol

Goal: starting from raw bytes flowing through a forwarder, end up with a
ProtoPoke protocol definition that decodes the messages into named,
typed fields.

This recipe assumes you already have a forwarder configured and at least
one session captured. If you do not, configure one with `add_forwarder`,
then `start_forwarder` and drive the client until you have a few dozen
frames.

## 1. Get a coarse picture of the traffic

```text
proxy_status                                  # confirm sessions exist
list_sessions                                 # pick a session_id
get_session_summary(session_id)               # frame count, durations
get_frame_stats(session_id=session_id)        # per-direction length / entropy
```

If `get_frame_stats` reports very uniform lengths the protocol is likely
fixed-format; widely varying lengths suggest length-prefixed or
delimiter-framed messages.

## 2. Decide on a framer

If frames look length-prefixed, try a candidate header offset:

```text
find_length_fields(session_id=session_id)     # ranked length-field candidates
```

Then change the forwarder's framer:

```text
list_framers                                  # see registered framers
update_forwarder_config(name, framer="length_prefix",
                        framer_options={"size": 2, "endianness": "big"})
```

For text-style protocols use `delimiter` with `\r\n` or `\n`. For
anything stranger, write a custom framer using the `framers` authoring
guide (`protopoke://guides/framers`) and load it with `set_framer`.

Re-capture a few frames and confirm `get_frames` now returns one logical
message per frame.

## 3. Cluster frames into message types

```text
cluster_frames(session_id=session_id)         # group by length / leading bytes
```

Each cluster is a candidate message type. Cross-check with:

```text
analyze_byte_ranges(session_id=session_id, bucket_id=<id>)
entropy_map(session_id=session_id, bucket_id=<id>)
```

Look for:

- **Constant bytes** (range size 1) — magic numbers, opcode bytes. These
  become `match` criteria for the message type.
- **Low-entropy, narrow-range bytes** — enums, flags.
- **High-entropy bytes** — IDs, hashes, ciphertext, payload.
- **Monotonically growing values** — sequence numbers, timestamps.

## 4. Hunt for length fields and references

```text
find_length_fields(session_id=session_id, bucket_id=<id>)
offset_correlations(session_id=session_id, bucket_id=<id>)
```

`offset_correlations` surfaces pairs of offsets whose values move
together — often a length field at offset N and a payload that ends at
that length. Use this to spot variable-length sections inside otherwise
fixed messages.

## 5. Diff two frames in the same cluster

```text
compare_frames(frame_id_a, frame_id_b)
diff_frames_in_bucket(session_id=session_id, bucket_id=<id>)
```

Bytes that differ are user data or per-session state; bytes that stay
the same are protocol structure. This is the single most reliable way
to draw field boundaries.

## 6. Sketch the first definition

Read the protocol-definition authoring guide for the YAML schema:

```text
list_authoring_guides
get_authoring_guide("protocol-definitions")   # or protopoke://guides/protocol-definitions
```

Then either build it incrementally in memory:

```text
create_protocol_definition(name="MyProto", endianness="big")
add_message_definition(name="LoginRequest", match={"type": "magic", "offset": 0, "value": [1]})
add_field_to_message("LoginRequest", {"name": "msg_type", "type": "uint8"})
add_field_to_message("LoginRequest", {"name": "username_len", "type": "uint16"})
add_field_to_message("LoginRequest", {"name": "username", "type": "bytes", "length": "username_len"})
```

or write a YAML file by hand and load it with `set_protocol_file`.

Use `list_field_types` if you forget which field types are available.

## 7. Validate against real frames

```text
decode_frames(session_id=session_id, limit=10)
```

For every frame check:

- It matched **one** message type (no `_no_match`).
- Field values look sensible (lengths match payload sizes, strings are
  printable, enums fall in range).
- No trailing bytes (the parser consumed the whole frame).

If something is wrong, edit the definition in memory
(`update_field_in_message`, `update_message_definition`,
`reorder_message_definition`) and re-run `decode_frames`. Iterate until
the whole capture decodes cleanly.

## 8. Persist

```text
save_protocol_to_file(path="my_proto.yaml")
```

From now on `set_protocol_file("my_proto.yaml")` brings the decoder
back, and every captured frame on every forwarder using this protocol
will decode with named fields visible in `get_frames`,
`tamper_decode_pending`, and the Traffic tab.

## Cross-references

- Authoring guide: `protopoke://guides/protocol-definitions`
- Authoring guide: `protopoke://guides/framers`
- Tool index: `protopoke://tools`
