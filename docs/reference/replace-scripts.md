---
title: "Custom Replace Scripts"
---

A **script** replace rule runs a Python function you write against every
frame in scope. It is the most powerful of the three replace-rule types
(binary / regex / script): unlike pattern matching, a script can actually
*parse* a message — so it can edit nested length-prefixed fields, maintain
state across frames, and stash values for later use in Forge.

This page is the reference for writing those scripts. For how to *add* a
script rule, see [Intercept in the UI](/ui/intercept#replace-rules) or
[Intercept in the Core library](/core/intercept#script-rules).

## The `apply()` function

Your script file must define exactly this function:

```python
def apply(data: bytes, variables: dict) -> bytes:
    ...
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `bytes` | The raw frame bytes to transform |
| `variables` | `dict` | A shared global variable store (see below) |

It must return `bytes` or `bytearray`. Returning anything else is treated as
an error and the original frame is passed through unchanged.

**Minimal example** — XOR every byte with `0xAA`:

```python
def apply(data: bytes, variables: dict) -> bytes:
    return bytes(b ^ 0xAA for b in data)
```

## The `variables` store

`variables` is a **shared dictionary** that persists across every rule
application in every pipeline (traffic, tamper, forge). All script rules in
the same session share it — a mutation made by one rule is immediately
visible to every other rule.

This is how you extract state from live traffic and reuse it later. Values
stored here are also accessible as `{{VARIABLE_NAME}}` placeholders in
[Forge playbook frames](/core/forge#variables).

**Capture a session token from the server, reuse it in client frames:**

```python
# capture_token.py — applied in the traffic pipeline, SERVER_TO_CLIENT direction
def apply(data: bytes, variables: dict) -> bytes:
    # Server sends: 0x02 <4-byte token> ...
    if len(data) >= 5 and data[0] == 0x02:
        variables["session_token"] = data[1:5].hex()
    return data  # pass through unchanged
```

```python
# inject_token.py — applied in the traffic pipeline, CLIENT_TO_SERVER direction
def apply(data: bytes, variables: dict) -> bytes:
    token_hex = variables.get("session_token")
    if token_hex and len(data) >= 5:
        return data[0:1] + bytes.fromhex(token_hex) + data[5:]
    return data
```

## Module-level state

The script is loaded as a Python module, so any code at module level runs
**once** when the rule is first applied. Use it for state that must survive
between calls without polluting `variables`:

```python
# sequence_counter.py
import struct
from collections import defaultdict

_counters = defaultdict(int)   # module-level — not reset between frames

def apply(data: bytes, variables: dict) -> bytes:
    direction = variables.get("direction", "unknown")
    _counters[direction] += 1
    return struct.pack(">I", _counters[direction]) + data[4:]
```

## Error handling and auto-reload

If `apply()` raises, ProtoPoke:

1. Logs the error (visible on the Logs tab).
2. **Clears the cached module** so the next frame reloads the script from
   disk.
3. Passes the original frame bytes through unchanged.

The practical upshot: you can fix a bug in the script file and the updated
version is picked up automatically on the next frame — no need to restart the
proxy or re-add the rule. The same auto-reload happens if the file is missing
or fails to import.

## Resetting script state

To force a reload (discarding module-level state) without waiting for an
error:

```python
rule = api.rules_engine.get_rule(rule_id)
rule.reset_script_state()
```

In the UI this is the **🔄 Reset** button on the replace-rules table. After a
reset, the next frame re-executes all module-level code.

## A complete example

The repo ships a real, non-trivial script:
[`examples/scripts/dns_a_to_localhost.py`](https://github.com/beaujeant/protopoke/blob/main/examples/scripts/dns_a_to_localhost.py)
parses a DNS message, walks the question/answer/authority/additional
sections, and rewrites RDATA to `127.0.0.1` *only* for `TYPE=A`, `CLASS=IN`,
`RDLENGTH=4` records — leaving AAAA, CNAME, MX, the question section, and
compression pointers untouched. The [DNS guide](/guides/dns) walks
through why a binary or regex rule cannot do this correctly and a script can.
