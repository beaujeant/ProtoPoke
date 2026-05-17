# Replay a Session with Mutation

Goal: take a session you captured once and replay it many times against
a target, with frames mutated each time to stress-test the server.

ProtoPoke gives you three replay surfaces, in increasing order of
control:

1. **`forge_session`** — re-send every (or selected) frames of a
   captured session against the original (or override) target. Best
   for "does my recording reproduce?" sanity checks.
2. **Playbooks** — name a sequence of frames and parameterise it with
   `{{VARIABLE}}` placeholders. Best for tests you want to run by
   hand, edit, or share.
3. **`fuzz_start`** — runs a captured session repeatedly under a chain
   of mutators and reports anomalies. Best for stress / vulnerability
   discovery.

You almost always use them in that order during a job: forge to confirm
your capture is replayable, playbook to parameterise the bits that
change per run, and fuzz to actually break things.

## 1. Capture a clean baseline

You need at least one session that exercises the flow you want to
fuzz — login, place order, send chat message, etc. Drive it through a
forwarder until you have the frames, then check the capture:

```text
list_sessions
get_session_summary(session_id)
get_frames(session_id, direction="client_to_server")
```

If the flow includes a per-session token (login response that the
client must echo back), note its frame and offset — you'll need a
variable for it in step 3.

## 2. Confirm the capture replays

The cheapest sanity check is to forge the whole captured client-side:

```text
forge_session(session_id=<id>,
              direction="client_to_server",
              frame_delay=0.05)
```

Inspect the returned `ForgeResult.frames` for non-zero `bytes_sent` and
no `error` fields. Look at the corresponding fresh capture session in
`list_sessions` to see the server's actual replies — if they match the
original, your capture is replayable as-is and you can skip straight to
fuzzing. If they don't, the protocol has session-unique tokens you'll
need to handle with variables (step 3).

For an isolated re-send of a single frame:

```text
send_frame(data_hex="…", host="…", port=…)
```

## 3. Parameterise with variables (playbooks)

A playbook is a named, replayable sequence with `{{VARIABLE}}`
placeholders. Promote one captured frame at a time:

```text
frame_to_forge(session_id=<id>, frame_id=<id>)        # returns the new playbook
```

This creates a one-frame playbook targeting the same host:port (and
TLS / transport) as the original session. Add more frames by editing
the playbook (`update_playbook`) or chain several `frame_to_forge`
calls and merge them. Build a multi-frame playbook from scratch with:

```text
create_playbook(label="login_flow",
                host="127.0.0.1", port=1234,
                data_hex="01 00 05 61 6c 69 63 65",
                response_window=1.0)
```

Replace the bits that change per run (sequence numbers, session IDs,
checksums) with `{{NAME}}` placeholders inside the frame's `data_hex`,
then set the variable:

```text
set_variable(name="SESS", value_hex="deadbeef")   # values are hex
get_variables                                     # confirm
```

Placeholder syntax (full list in `protopoke://guides/replace-scripts`):

| Form | Effect |
|------|--------|
| `{{SESS}}` | Substitute the raw bytes stored under `SESS` |
| `{{SESS:uint32be_add(1)}}` | Decode as uint32 BE, add 1, re-encode |
| `{{SESS:xor(ff)}}` | XOR every byte of `SESS` with `0xff` |
| `{{SESS:script(value[::-1])}}` | Eval Python expression, must return bytes |

There is no `random_*` transform; if you want a fresh random value per
run, set the variable from a script-type replace rule **before** the
frame that needs it (see the script-replace guide).

Run the playbook once and check it reaches the server cleanly:

```text
run_playbook(playbook_id)
```

The returned `PlaybookRun.traffic` lists every send and response,
including bytes-sent / bytes-received / error fields.

## 4. Pick mutators

```text
list_mutators
```

Built-in mutators fall into two groups:

- **Raw** — `bit_flip`, `byte_insert`, `byte_delete`, `known_bad`,
  `radamsa`. Operate on byte buffers regardless of protocol. Cheap,
  always applicable.
- **Field-aware** — `field_boundary`, `field_overflow`, `null_byte`,
  `length_mangle`. Require a loaded protocol definition; they target
  named fields directly.

Field-aware mutators find bugs faster but only work if you've already
run the `reverse-engineer-unknown-protocol` recipe and loaded a
definition (loaded by the operator via the TUI or a ForwarderConfig.protocol_definition_path).

A productive default chain for an unknown protocol with a loaded
definition is `length_mangle` + `field_overflow` + `bit_flip`: those
three between them find the bulk of memory-safety and length-handling
bugs.

## 5. Start the campaign

`fuzz_start` operates on a **captured session** (not a playbook):

```text
fuzz_start(session_id=<id>,
           mutators=[{"name": "length_mangle"},
                     {"name": "field_overflow", "lengths": [256, 1024, 8192]},
                     {"name": "bit_flip", "count": 2}],
           iterations=500,
           stop_on_crash=True,
           response_timeout=5.0)
```

To replay against a different target than the original, set
`server_host` / `server_port`. To fuzz only some frames, set
`frame_selector="0,2-4"` (everything else is sent unmutated).

`fuzz_start` returns immediately with a `campaign_id` — the campaign
runs as a background asyncio task.

## 6. Watch + collect

```text
fuzz_status(campaign_id)                # progress, current iteration, counts
fuzz_results(campaign_id,
             interesting_only=True)     # only flagged iterations
fuzz_stop(campaign_id)                  # halt early
list_campaigns                          # history
```

`fuzz_results` flags an iteration as `interesting` when any of these
happen, all worth investigating:

- **`connection_reset`** mid-frame — likely server-side parse error
  (use-after-free, OOB write, bad cast).
- **`timeout`** with no response — possible DoS or infinite loop in
  the server's parser.
- **Response size anomaly** vs baseline — possible buffer disclosure
  or alternate code path (error vs success).
- **Status changes** — the campaign exits with status `crashed` if
  `stop_on_crash` was set and a connection reset happened.

## 7. Reproduce a finding

Every fuzz iteration records the exact bytes that were sent. Pull the
offending iteration's `mutated_bytes_hex` out of `fuzz_results` and
reproduce with either:

```text
send_frame(data_hex=<hex>, host=<h>, port=<p>)        # one-shot
create_playbook(label="repro_iter_42", host=<h>, port=<p>,
                data_hex=<hex>)                       # persisted test case
```

For protocol-aware reproductions, decode the bytes into fields, edit
them by name, and re-encode using a playbook with `{{VARIABLE}}`
substitutions for the parts you'd like to vary.

## Cross-references

- Authoring guide: `protopoke://guides/protocol-definitions` (needed for
  field-aware mutators)
- Authoring guide: `protopoke://guides/replace-scripts` (for `{{VAR}}`
  helpers)
- Recipe: `protopoke://recipes/reverse-engineer-unknown-protocol`
- Recipe: `protopoke://recipes/validate-with-tamper`
- Tool index: `protopoke://tools`
