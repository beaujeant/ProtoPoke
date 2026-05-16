# Map the Protocol's State Machine

Goal: discover **which message types follow which** — the
conversation structure / state machine of the protocol. Per-frame
analysis tells you the shape of one message; state-machine analysis
tells you how a session unfolds and what the protocol "expects" at
each step.

This is what tools like Netzob, ScriptGen, and Discoverer call
"protocol-state inference". For ProtoPoke it's done by combining
clustering (to label each frame with a message type) with
direction-aware sequence inspection.

## Why bother

- **Replay** that respects sequence order is far more likely to be
  accepted than a flat firehose.
- **Fuzzing** is much more effective if you mutate the *last*
  message in a multi-step handshake — earlier frames are usually
  protocol prologue and only the later ones reach the real parser.
- **Field semantics** often depend on state: a `payload` field can be
  an enum in the handshake and a raw blob after authentication.
- **Authentication / authorisation** flaws often live in
  state-machine transitions (skipping a step, re-running a step,
  injecting a step from the wrong direction).

## 1. Capture a full, clean conversation

You need at least one session that covers the full lifecycle: connect,
handshake, authenticated work, disconnect. Drive it end-to-end through
a single forwarder.

```text
list_sessions
get_session_summary(session_id)              # check both directions are populated
```

## 2. Build a message-type label for every frame

Cluster each direction independently:

```text
cluster_frames(session_id=session_id, direction="client_to_server")
cluster_frames(session_id=session_id, direction="server_to_client")
```

Assign each cluster a short label by its prefix and size:

```
C2S: C01_HELLO    (prefix 01, size 16)
C2S: C02_AUTH     (prefix 02, size 80)
C2S: C03_SUB      (prefix 03, size 24)
S2C: S81_HELLO_OK (prefix 81, size 12)
S2C: S82_CHAL     (prefix 82, size 32)
S2C: S83_AUTH_OK  (prefix 83, size 8)
```

Per-direction labels make the conversation symmetric and easy to read.
Note the message **size** alongside the prefix — many protocols reuse a
prefix byte for different shapes.

## 3. Walk the conversation in capture order

```text
get_frames(session_id, limit=200)           # default order is capture order
```

Map each frame to its cluster label (you can do this in the chat or
in scratch state). The result is a transcript:

```
1. C2S C01_HELLO         01 02 ...
2. S2C S81_HELLO_OK      81 ...
3. C2S C02_AUTH          02 41 6c 69 63 65 ...
4. S2C S82_CHAL          82 ab cd ef ...
5. C2S C02_AUTH          02 41 6c 69 63 65 ... (response to challenge)
6. S2C S83_AUTH_OK       83 ...
7. C2S C03_SUB           03 ...
8. S2C S84_DATA          84 ...
   ...
```

Two things to look for in the transcript:

- **Request/response pairs**: each client message is followed by
  exactly one server message. That's a synchronous RPC pattern. If
  some client messages have no reply, that's a one-way / fire-and-forget
  channel.
- **Out-of-band server messages**: server frames that don't follow a
  client message — those are pushes / notifications / heartbeats.

## 4. Validate request/response pairing

Pair adjacent frames and diff them:

```text
compare_frames(session_id, frame_id_a=<C2S_frame>, frame_id_b=<S2C_frame>)
```

Bytes that **match** between the request and the response are usually
a transaction / sequence ID echoed back. Confirming this gives you a
free annotation:

```text
update_field_in_message(message_name="C02_AUTH",
                        field_name="unknown_2",
                        field={"name": "txn_id", "type": "uint32"})
update_field_in_message(message_name="S82_CHAL",
                        field_name="unknown_2",
                        field={"name": "txn_id", "type": "uint32"})
```

Use `offset_correlations` to confirm a putative txn ID at offset A in
the request matches offset B in the response across many frames:

```text
offset_correlations(session_id=session_id,
                    offset_a=2, type_a="uint32_be",
                    offset_b=2, type_b="uint32_be",
                    direction=None)         # cross-direction
```

(Pearson `r` ≈ 1.0 confirms the pairing.)

## 5. Identify periodic / keep-alive messages

Frames that appear at near-uniform intervals with no triggering client
action are heartbeats. Find them by comparing the timestamps of
consecutive frames in one cluster:

```text
filter_frames(session_id=session_id,
              byte_patterns=[{"offset": 0, "hex": "FE"}],
              limit=200)
```

A near-constant `timestamp` delta between consecutive `FE…` frames
identifies a periodic message. Drop them when describing the state
machine — they're not transitions.

## 6. Distil the state machine

For each non-heartbeat C2S cluster, list the S2C clusters that follow
it in the transcript. A useful representation:

```
C01_HELLO         → S81_HELLO_OK
C02_AUTH (req)    → S82_CHAL
C02_AUTH (resp)   → S83_AUTH_OK | S8F_AUTH_FAIL
C03_SUB           → S84_DATA*
```

If the same client message produces different server messages depending
on prior state, that's a stateful transition — note it. The conversation
graph you've drawn is the state machine.

## 7. Use it

The map pays for itself in three workflows:

- **Replay**: use `forge_session` with `frame_selector` to send only the
  frames up to and including the state you want to reach, then probe
  from there.
- **Playbook**: capture the prologue once into a playbook, leave the
  later frames `{{VARIABLE}}`-templated, and run that prologue before
  every fuzz iteration via the variable-store / playbook combo.
- **Fuzzing**: with `fuzz_start`, use `frame_selector` to keep the
  prologue frames untouched and only mutate the later "real" messages —
  this is what gets you past the protocol's front gate.

## Cross-references

- Recipe: `protopoke://recipes/reverse-engineer-unknown-protocol`
- Recipe: `protopoke://recipes/replay-with-mutation`
- Recipe: `protopoke://recipes/validate-with-tamper`
- Tool index: `protopoke://tools`
