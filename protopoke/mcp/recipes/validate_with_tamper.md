# Validate a Hypothesis with Active Probing

Goal: confirm (or refute) a guess about a field's semantics by
**changing it in flight** and observing the server's reaction. This is
the active-probing counterpart to passive analysis — it turns a
decoded-cleanly definition into a known-correct one.

Why this matters: a passive analysis can produce a definition that
decodes every captured frame without error and still be wrong. The
canonical example is a "length" field that happens to equal `len(frame)
- 4` in every captured frame but is actually a payload-count, not a
byte-length. Passive analysis cannot distinguish those. Active probing
can.

The pattern below is the network equivalent of Burp Suite's Repeater
+ Intercept, scripted via MCP so an AI can run it autonomously.

## Prerequisites

- A protocol definition loaded by the operator (via the TUI or by
  pointing a `ForwarderConfig.protocol_definition_path` at a YAML
  file).  The MCP server has no write path for definitions; without
  one loaded, you can probe by raw bytes via `tamper_modify_and_forward`,
  but `tamper_modify_field_and_forward` is much less error-prone.
- A live forwarder with at least one active session, so you can
  intercept the next message of interest.

## 1. Pick the field and the probe

For every field type, pick a probe that maximises the **information**
of the server's reaction:

| Hypothesis             | Probe                                              | Confirming reaction |
|------------------------|----------------------------------------------------|---------------------|
| Length-of-payload      | Increment by ±1                                    | Truncation, parse error, or hang |
| Count-of-elements      | Set to a value inconsistent with payload bytes     | Different parse error than length |
| Magic / version        | Flip a byte                                        | Hard reject ("unknown version") |
| Enum / opcode          | Set to an unused value                             | "Unknown command" error |
| String / username      | Use `"x" * 1000` or non-UTF8 bytes                 | Error often names the field |
| Numeric ID / handle    | Set to 0xFFFFFFFF                                  | "Invalid ID" — confirms it's a handle |
| Checksum / MAC         | XOR a single byte                                  | Hard reject — confirms it guards integrity |
| Timestamp              | Set to far past / future                           | Clock-skew error or auth replay reject |
| Encrypted ciphertext   | Flip one byte                                      | Decryption error vs garbled but accepted |

The principle is: pick a probe whose two possible reactions
(accept vs reject) come from **different code paths**, so the reaction
disambiguates your hypotheses.

## 2. Narrow the intercept to the next interesting frame

You want to catch one specific frame, not the whole stream.

```text
tamper_toggle(enabled=True)
clear_intercept_rules                                    # start fresh

# Catch only the message type you care about (opcode 0x01 = login):
add_intercept_rule(label="probe_login",
                   pattern="01",
                   action="intercept",
                   direction="client_to_server")

# Optional: auto-forward everything else explicitly:
add_intercept_rule(label="rest", pattern="",
                   action="forward",
                   direction="client_to_server")

# Optional: scope to one session you control:
tamper_set_session_filter(session_ids=[session_id])
```

## 3. Drive the client to send the frame

Trigger the action from the actual client (run the login, send the
chat, click the button). The next matching frame will land in the
tamper queue.

```text
list_intercepted                                # poll until non-empty
tamper_decode_pending                           # see the parsed fields
```

If the queue stays empty, your intercept rule isn't matching: re-check
the `pattern` (it's a binary-pattern string, not raw hex) and the
direction filter.

## 4. Apply the probe

For a field-level probe (preferred when you have a protocol
definition):

```text
tamper_modify_field_and_forward(
    unit_id=<unit>,
    field_edits={"payload_len": <orig_value + 1>},   # length probe
)
```

For a raw-byte probe (when you don't have a definition, or you want to
clobber a specific offset):

```text
# Original bytes were "01 00 0A 68 65 6c 6c 6f 21 21 21 21 21" — flip byte at offset 2:
tamper_modify_and_forward(unit_id=<unit>,
                          new_bytes_hex="01 00 0B 68 65 6c 6c 6f 21 21 21 21 21")
```

Or drop the frame to confirm the server actually notices the missing
message:

```text
tamper_drop(unit_id=<unit>)
```

## 5. Observe the reaction

Watch for the server's response in the **same** session:

```text
list_sessions                                  # the session is still open
get_session_summary(session_id)                # frame count delta
get_frames(session_id, direction="server_to_client")
decode_frames(session_id, direction="server_to_client")
```

Compare with a known-good baseline (a previous, unmodified login). If
you don't have one, do the same probe at a baseline value first so you
can diff. Useful diffs:

```text
compare_frames(session_id, frame_id_a=<baseline_resp>, frame_id_b=<probed_resp>)
```

A change in response opcode or error code is the gold standard:
the server's parser actually went down a different branch. A
connection drop also confirms the field matters; a silent accept means
your probe didn't tickle the field — pick a more aggressive probe and
repeat.

## 6. Record the confirmation

A confirmed hypothesis goes from "looks like" to **documented**.  Two
places to record it:

- **Knowledge base** (preferred, persistent across sessions):
  ```text
  add_finding(title="payload_len at offset 2",
              status="confirmed", confidence="high",
              message_name="LoginRequest", field_name="payload_len",
              evidence_frame_ids=["...", "..."],
              description="Probed +1: server truncated. Probed -1: parse error.")
  ```
  If you had a prior hypothesis, update it instead of creating a new one:
  ```text
  update_finding(finding_id="...", status="confirmed", confidence="high")
  ```
- **Protocol definition YAML**: rename a guess like `unknown_3` to its
  real meaning (`payload_len`, `transaction_id`, …) and hand the
  updated YAML to the operator in chat — they save and reload it.
  ProtoPoke does not expose any MCP tool to mutate the loaded
  definition.

## 7. Clean up

Probes should be reversible. Tear down the intercept rule when you're
done so the next session isn't paused unexpectedly:

```text
clear_intercept_rules
tamper_toggle(enabled=False)
```

## Productivity tips for AI agents

- **One probe per cycle**. Don't change two fields at once — you can't
  tell which one drove the reaction.
- **Hold a baseline**. Before every probe, replay or capture an
  unprobed run so you can diff.
- **Triangulate at boundaries**. For numeric fields, probe with `0`,
  `1`, `MAX`, `MAX-1`, and the original value. Most parser bugs live
  at boundaries.
- **Drop, don't modify, to confirm direction**. Dropping the frame
  is the cleanest test that the server actually expects it.
- **Use `replay_with_field_edits`** for *repeated* probes against a
  recorded session — no need to drive the client by hand each time.

## Cross-references

- Recipe: `protopoke://recipes/intercept-and-rewrite`
- Recipe: `protopoke://recipes/reverse-engineer-unknown-protocol`
- Authoring guide: `protopoke://guides/protocol-definitions`
- Tool index: `protopoke://tools`
