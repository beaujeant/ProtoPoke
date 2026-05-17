# Intercept and Rewrite Frames

ProtoPoke offers three different mechanisms for changing frames as they
flow through a forwarder. Picking the right one matters — they have
very different ergonomics and performance.

## Choosing the right mechanism

| Need                                                          | Use                                |
|---------------------------------------------------------------|------------------------------------|
| Always replace bytes X with bytes Y, unattended               | **Replace rule**                   |
| Pause every matching frame so an operator (or AI) edits it    | **Intercept rule** + tamper queue  |
| Stateful or conditional rewriting (counters, lookups, crypto) | **Script replace rule** (UI only)  |

Replace rules and intercept rules can both be added via MCP. Script
rules execute arbitrary Python in the proxy process, so they cannot
be registered from MCP — the operator must load the script in the UI.

## Mechanism 1: replace rule (unattended find/replace)

Best for: protocol downgrade, debug-flag flip, hard-coded credential
substitution, stripping a known prefix.

The replace-rule "pattern" is a binary-pattern string (see
`protopoke://guides/replace-scripts` for the full grammar; the short
version is: hex byte pairs separated by spaces, `??` for any byte,
`[00-0F]` for ranges).

```text
add_replace_rule(
    label="downgrade_tls_flag",
    pattern="03 03",                        # match these two bytes anywhere
    replacement_hex="0301",                 # replacement bytes as hex
    direction="client_to_server",           # or "server_to_client", or omit for both
    enabled=True,
)
list_replace_rules
update_replace_rule(rule_id, enabled=False) # toggle without removing
remove_replace_rule(rule_id)
reorder_replace_rule(rule_id, new_index=0)  # rules run top to bottom
clear_replace_rules
```

Rules are applied to every matching frame, on every session, without
human action. Order matters: later rules see the **output** of earlier
ones, so a careless rule pair can loop a value back to itself.

## Mechanism 2: intercept rule + tamper queue (human-in-the-loop)

Best for: exploring a protocol, one-off edits, watching the response to
specific changes, confirming a hypothesised field semantics.

Step A — turn the tamper queue on:

```text
tamper_toggle(enabled=True)
tamper_status                                # confirm enabled
```

Step B — narrow what gets queued. With no rules **every** frame is
intercepted (in the chosen direction), which quickly becomes
unmanageable. Use first-match `intercept` / `forward` rules to scope:

```text
# Intercept only frames starting with opcode 0x01:
add_intercept_rule(label="only_login_frames",
                   pattern="01",
                   action="intercept",
                   direction="client_to_server")

# Optionally auto-forward everything else by adding a catch-all:
add_intercept_rule(label="rest",
                   pattern="",                  # empty == match all
                   action="forward",
                   direction="client_to_server")

tamper_set_direction_filter("client_to_server")
tamper_set_session_filter(session_ids=[session_id])
```

Step C — wait for frames, then process them:

```text
list_intercepted                            # pending frames + unit_id
tamper_decode_pending                       # same, with parsed protocol view

# Forward / drop / modify by unit_id:
tamper_forward(unit_id=<unit>)
tamper_drop(unit_id=<unit>)

# Raw byte edit (use when you don't have a protocol definition):
tamper_modify_and_forward(unit_id=<unit>, new_bytes_hex="deadbeef")

# Protocol-aware field edit (requires the operator to have loaded a protocol definition):
tamper_modify_field_and_forward(
    unit_id=<unit>,
    field_edits={"username": "admin", "msg_type": 2},
)

# Flush everything that's pending:
tamper_forward_all
```

`tamper_modify_field_and_forward` re-encodes the frame using the loaded
protocol definition, so length fields update automatically. Use it
whenever the change is "edit field X to value Y" — far less error-prone
than recomputing the raw bytes by hand.

## Mechanism 3: script replace rule (stateful / conditional)

Best for: response replay attacks, per-session counters, crypto,
lookups against external data, anything that needs more than a fixed
find/replace.

Step A — write the script (see `protopoke://guides/replace-scripts`
for the full spec). The skeleton:

```python
def apply(data: bytes, variables: dict[str, str]) -> bytes:
    # Return new bytes (or `data` unchanged).
    # `variables` is the shared {{VARIABLE}} table from set_variable.
    return data
```

Step B — quote the loading steps to the operator:

```text
get_script_load_instructions                # returns ui_path + steps + notes
```

ProtoPoke deliberately does not expose an MCP tool to register script
rules because they execute arbitrary Python in the proxy process. The
operator must select the file in the UI.

Step C — once loaded, the script rule appears in `list_replace_rules`.
You can still toggle / rename it via `update_replace_rule`; only the
script body itself has to be edited on disk (it auto-reloads on the
next matching frame).

## Combining mechanisms

The mechanisms run in this order, per frame, per direction:

1. **Replace rules** in `list_replace_rules` order — outputs feed into
   the next rule.
2. **Intercept rules** decide (first-match) whether to queue the result
   for human / AI editing via tamper.
3. **Tamper queue** holds the frame until released; the released bytes
   are what reach the other side.

So a script rule can normalise inputs, a binary rule can clean up a
fixed marker, and the tamper queue still gets a chance to edit the
final form. Keep this ordering in mind when designing the rule set.

## Active probing pattern

The most useful AI workflow combines all of this with a captured
session: load a protocol definition, intercept the next message of
interest, change one field, observe the response, drop the rule.
This is the fastest way to confirm field semantics without writing a
fuzzer — see `protopoke://recipes/validate-with-tamper`.

## Cross-references

- Authoring guide: `protopoke://guides/replace-scripts`
- Authoring guide: `protopoke://guides/protocol-definitions` (needed for
  `tamper_modify_field_and_forward`)
- Recipe: `protopoke://recipes/validate-with-tamper`
- Tool index: `protopoke://tools`
