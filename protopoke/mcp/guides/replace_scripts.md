# Authoring a Custom Replace Script

A **script** replace rule runs a Python function you write against every
frame in scope. It is the most powerful of the three replace-rule types
(binary / regex / script): unlike pattern matching, a script can actually
*parse* a message — so it can edit nested length-prefixed fields, maintain
state across frames, and stash values for later use in Forge.

## For MCP Clients (read this first)

ProtoPoke deliberately does **not** expose any MCP tool to write a script
file to disk or to register a script replace rule. Script rules execute
arbitrary Python inside the proxy process, so the operator — not the AI —
must be the gate that lets code run.

The intended flow when a user asks you to author a script rule:

1. Fetch what you need to reason about the frame:
   `get_protocol_definition()` for field offsets/types, plus any relevant
   captured frames via the analysis tools.
2. Generate the full `apply(data, variables)` script and display it back
   to the user in a fenced ```python code block. Do not truncate.
3. Hand off to the operator with explicit load instructions — call
   `get_script_load_instructions()` and quote the steps it returns so the
   user knows exactly where to click in the UI.
4. Stop. Do not try to persist the file, do not call `add_replace_rule`
   to fake a script rule, and do not poll for the rule to appear.

The MCP `add_replace_rule` tool only handles `binary` rules (pattern +
hex replacement) by design. If the transformation can be expressed as a
binary or regex find-and-replace, prefer that — it does not execute code
and can be registered directly.

## The `apply()` Function

Your script file must define exactly this function:

```python
def apply(data: bytes, variables: dict) -> bytes:
    ...
```

| Parameter   | Type    | Description                                |
|-------------|---------|--------------------------------------------|
| `data`      | `bytes` | The raw frame bytes to transform           |
| `variables` | `dict`  | A shared global variable store (see below) |

It must return `bytes` or `bytearray`. Returning anything else is treated
as an error and the original frame is passed through unchanged.

**Minimal example** — XOR every byte with `0xAA`:

```python
def apply(data: bytes, variables: dict) -> bytes:
    return bytes(b ^ 0xAA for b in data)
```

## The `variables` Store

`variables` is a **shared dictionary** that persists across every rule
application in every pipeline (traffic, tamper, forge). All script rules in
the same session share it — a mutation made by one rule is immediately
visible to every other rule.

This is how you extract state from live traffic and reuse it later. Values
stored here are also accessible as `{{VARIABLE_NAME}}` placeholders in
Forge playbook frames.

### Capture-then-reuse pattern

Capture a session token from the server, reuse it in client frames:

```python
# capture_token.py — server_to_client direction
def apply(data: bytes, variables: dict) -> bytes:
    # Server sends: 0x02 <4-byte token> ...
    if len(data) >= 5 and data[0] == 0x02:
        variables["session_token"] = data[1:5].hex()
    return data  # pass through unchanged
```

```python
# inject_token.py — client_to_server direction
def apply(data: bytes, variables: dict) -> bytes:
    token_hex = variables.get("session_token")
    if token_hex and len(data) >= 5:
        return data[0:1] + bytes.fromhex(token_hex) + data[5:]
    return data
```

## Module-Level State

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

## Error Handling & Auto-Reload

If `apply()` raises, ProtoPoke:

1. Logs the error (visible on the Logs tab).
2. **Clears the cached module** so the next frame reloads the script from
   disk.
3. Passes the original frame bytes through unchanged.

The practical upshot: you can fix a bug in the script file and the
updated version is picked up automatically on the next frame — no need to
restart the proxy or re-add the rule. The same auto-reload happens if the
file is missing or fails to import.

## Resetting Script State

To force a reload (discarding module-level state) without waiting for an
error:

```python
rule = api.rules_engine.get_rule(rule_id)
rule.reset_script_state()
```

In the UI this is the **🔄 Reset** button on the replace-rules table.
After a reset, the next frame re-executes all module-level code.

## Authoring Tips

- **Pass through by default**: when the frame is not relevant, `return
  data` unchanged. Only modify what you intend to change.
- **Validate before mutating**: check `len(data)` and opcode bytes before
  slicing — frames in scope may include shapes you did not anticipate.
- **Avoid I/O and blocking calls**: the script runs on the asyncio event
  loop; sleeping or doing network I/O stalls every connection.
- **Recompute length fields after edits**: if you change a payload length,
  update the matching length-prefix bytes — or use a protocol definition
  and `tamper_modify_field_and_forward`, which recomputes lengths
  automatically.
- **Keep scripts idempotent**: the same frame may be re-played via Forge
  many times; do not assume a script runs exactly once per logical message.
- **Stash useful values in `variables`**: anything you put there becomes
  available to other scripts and to `{{NAME}}` placeholders in Forge.

## Complete Example

The repo ships a real, non-trivial script:
`examples/scripts/dns_a_to_localhost.py`. It parses a DNS message, walks
the question / answer / authority / additional sections, and rewrites
RDATA to `127.0.0.1` *only* for `TYPE=A`, `CLASS=IN`, `RDLENGTH=4`
records — leaving AAAA, CNAME, MX, the question section, and compression
pointers untouched. Read it as a template for parsing-aware rewriting.
