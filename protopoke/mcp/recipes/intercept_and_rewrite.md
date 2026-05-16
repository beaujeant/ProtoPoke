# Intercept and Rewrite Frames

ProtoPoke offers three different mechanisms for changing frames as they
flow through a forwarder. Picking the right one matters — they have
very different ergonomics and performance.

## Choosing the right mechanism

| Need                                            | Use                  |
|-------------------------------------------------|----------------------|
| Always replace bytes X with bytes Y, unattended | **Replace rule**     |
| Pause every matching frame so a human edits it  | **Intercept rule** + tamper queue |
| Stateful or conditional rewriting (counters, lookups, crypto) | **Script replace rule** |

Replace rules and intercept rules can both be added either via the UI
(Tamper tab) or via MCP tools. Script rules require a Python file on
disk that the operator must load through the UI — see
`get_script_load_instructions`.

## Mechanism 1: replace rule (unattended find/replace)

Best for: protocol downgrade, debug-flag flip, hard-coded credential
substitution.

```text
add_replace_rule(
    label="downgrade_tls_flag",
    mechanism="binary",                     # "binary" | "regex" | "script"
    find_hex="0303",
    replace_hex="0301",
    direction="client_to_server",           # or "server_to_client" or omit for both
    scope=["traffic"],                      # "traffic" | "tamper" | "forge"
)
list_replace_rules
update_replace_rule(rule_id, ...)
remove_replace_rule(rule_id)
reorder_replace_rule(rule_id, position=0)   # rules run top to bottom
clear_replace_rules
```

Rules are applied to every matching frame, on every session, without
human action. Order matters: later rules see the output of earlier ones.

## Mechanism 2: intercept rule + tamper queue (human-in-the-loop)

Best for: exploring a protocol, one-off edits, watching the response to
specific changes.

Step A — turn the tamper queue on:

```text
tamper_toggle(enable=True)
tamper_status                                # confirm enabled
```

Step B — narrow what gets queued (optional but recommended):

```text
add_intercept_rule(
    label="only_login_frames",
    direction="client_to_server",
    match_hex="0100",                       # frame begins with these bytes
)
tamper_set_direction_filter("client_to_server")
tamper_set_session_filter(session_id)
```

Without intercept rules, **every** frame in the chosen direction is
queued — that quickly becomes unmanageable on a busy connection.

Step C — wait for frames, then process them:

```text
list_intercepted                            # pending frames
tamper_decode_pending(unit_id)              # parse before editing
tamper_modify_field_and_forward(
    unit_id,
    field_name="username",
    new_value="admin",
)
# or change raw bytes:
tamper_modify_and_forward(unit_id, new_data_hex="deadbeef")
# or pass it through unchanged:
tamper_forward(unit_id)
# or drop:
tamper_drop(unit_id)
# or flush everything:
tamper_forward_all()
```

`tamper_modify_field_and_forward` re-encodes the frame using the loaded
protocol definition, so length fields update automatically. Use it
whenever the change is "edit field X to value Y" — far less error-prone
than recomputing the raw bytes.

## Mechanism 3: script replace rule (stateful / conditional)

Best for: response replay attacks, per-session counters, crypto, lookups
against external data.

Step A — write the script (see `protopoke://guides/replace-scripts` for
the full spec). It must define:

```python
def apply(data: bytes, variables: dict[str, str]) -> bytes:
    # Return new bytes (or `data` unchanged).
    # `variables` is the shared {{VARIABLE}} table from set_variable.
    ...
```

Step B — quote the loading steps to the operator:

```text
get_script_load_instructions                # returns ui_path + steps + notes
```

ProtoPoke deliberately does not expose an MCP tool to register script
rules because they execute arbitrary Python in the proxy process. The
operator must select the file in the UI.

Step C — once loaded, the script rule appears in `list_replace_rules`
with `mechanism="script"`. You can still update its scope/direction/
label via `update_replace_rule`; only the script body itself has to be
edited on disk (it auto-reloads on the next matching frame).

## Combining mechanisms

The three mechanisms run in this order, per frame, per direction:

1. **Replace rules** (in the order shown by `list_replace_rules`).
2. **Intercept rules** decide whether to queue the result for human
   editing via tamper.
3. **Tamper queue** holds the frame until released; the released bytes
   are what reach the other side.

So a script rule can normalise inputs, a binary rule can clean up a
fixed marker, and the tamper queue still gets a chance to edit the
final form. Keep this ordering in mind when designing the rule set.

## Cross-references

- Authoring guide: `protopoke://guides/replace-scripts`
- Authoring guide: `protopoke://guides/protocol-definitions` (needed for
  `tamper_modify_field_and_forward`)
- Tool index: `protopoke://tools`
