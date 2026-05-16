# Replay a Session with Mutation

Goal: take a session you captured once and replay it many times against
a target, with frames mutated each time to stress-test the server.

This combines three subsystems:

- **Forge** — re-sends frames in order.
- **Playbooks** — name a sequence of frames and parameterise it with
  `{{VARIABLE}}` placeholders.
- **Fuzzing** — runs a playbook (or session) repeatedly under a chain of
  mutators and reports anomalies.

## 1. Capture a clean baseline

You need at least one session that exercises the flow you want to
fuzz — login, place order, send chat message, etc. Drive it through a
forwarder until you have the frames.

```text
list_sessions
get_session_summary(session_id)
get_frames(session_id, limit=20)
```

## 2. Turn the session into a playbook

The easy path: build a playbook directly from captured frames.

```text
frame_to_forge(frame_id=<frame_id>, playbook_id=<existing-or-new>)
```

Call it once per frame you want in the playbook, in send order. Or
create the playbook explicitly first:

```text
create_playbook(name="login_flow",
                target_host="127.0.0.1", target_port=1234,
                frames=[
                    {"direction": "client_to_server",
                     "data_hex": "...", "wait_response": True},
                    ...
                ])
```

## 3. Parameterise with variables

Replace the bits that change per run (usernames, nonces, session IDs)
with `{{NAME}}` placeholders in `data_hex` or `data_text`.

```text
set_variable("USERNAME", "alice")
set_variable("NONCE", "{{random_hex:16}}")  # transforms also supported
get_variables                               # confirm
```

Inside a frame, the literal substring `{{USERNAME}}` is replaced at send
time. Supported transforms include `random_hex`, `random_int`, `now`,
and arithmetic over other variables — see the playbook reference for the
current set.

Run the playbook once to confirm it reaches the server cleanly:

```text
run_playbook(playbook_id)
```

Check the returned `frames` for non-zero `bytes_sent` and any
`error` fields. If you also want to see what the server replied, look
at the corresponding capture session in `list_sessions`.

## 4. Pick mutators

```text
list_mutators
```

Built-in mutators fall into two groups:

- **Raw** — `bit_flip`, `byte_insert`, `byte_delete`, `known_bad`,
  `radamsa`. Operate on byte buffers regardless of protocol.
- **Field-aware** — `field_boundary`, `field_overflow`, `null_byte`,
  `length_mangle`. Require a loaded protocol definition; they target
  named fields.

Field-aware mutators find bugs faster but only work if you've already
run the `reverse-engineer-unknown-protocol` recipe and loaded a
definition with `set_protocol_file`.

Chain several with `ChainMutator` to compose strategies.

## 5. Start the campaign

```text
fuzz_start(playbook_id=<id>,
           mutators=[{"name": "bit_flip", "params": {"rate": 0.01}},
                     {"name": "length_mangle"}],
           iterations=500,
           anomaly_detection=True)
```

Or fuzz a captured session directly without a playbook:

```text
fuzz_start(session_id=<id>, mutators=[...], iterations=500)
```

`fuzz_start` returns a `campaign_id`.

## 6. Watch + collect

```text
fuzz_status(campaign_id)                # progress, current iteration
fuzz_results(campaign_id)               # anomalies, crashes, slow responses
fuzz_stop(campaign_id)                  # halt early
list_campaigns                          # history
```

Anomalies worth attention:

- **Connection drops** mid-frame — likely server-side parse error.
- **Hangs** (no response within the campaign timeout) — possible DoS.
- **Response length spikes** — possible buffer disclosure.
- **Replies that decode to different message types than baseline** —
  state-machine confusion.

## 7. Reproduce a finding

Every fuzz iteration records the exact mutated frames. Pull the
offending iteration's frames out of `fuzz_results` and either:

- Send them directly with `send_frame` for a one-shot repro.
- Build a fresh playbook from them so it lives alongside your other
  test cases.

## Cross-references

- Authoring guide: `protopoke://guides/protocol-definitions` (needed for
  field-aware mutators)
- Recipe: `protopoke://recipes/reverse-engineer-unknown-protocol`
- Tool index: `protopoke://tools`
