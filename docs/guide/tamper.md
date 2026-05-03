# Tamper & Intercept

ProtoPoke can pause frames mid-stream, letting you inspect, modify, or drop them before they reach their destination. This is controlled through the **tamper system**, which consists of two parts: the **intercept queue** and the **rules engine**.

## Enabling Tamper Mode

=== "TUI"

    Tamper tab → toggle the tamper switch on

=== "Python API"

    ```python
    api.tamper_enabled = True
    ```

=== "MCP"

    ```
    tamper_toggle(enabled=true)
    ```

When tamper mode is enabled, all frames are held in a queue until you issue a verdict.

## Verdicts

For each intercepted frame, you can:

| Verdict | Effect |
|---------|--------|
| **Forward** | Send the frame as-is to its destination |
| **Drop** | Silently discard the frame |
| **Modify and forward** | Replace the raw bytes or edit named fields, then forward |

### Python API Example

```python
# Enable tamper
api.tamper_enabled = True

# Wait for the next intercepted frame
unit = await api.get_next_intercepted()
print(unit.frame.raw_bytes.hex())
print(unit.frame.direction)

# Forward as-is
api.forward(unit.id)

# Or drop it
api.drop(unit.id)

# Or modify raw bytes and forward
api.modify_and_forward(unit.id, new_bytes=b"\x01\x02\x03")

# Or modify a named protocol field (requires a protocol definition)
api.modify_field_and_forward(unit.id, {"username": "admin"})
```

## Intercept Rules

Intercept rules control **which frames are held** in the queue. Without rules, all frames are intercepted when tamper mode is on. Rules let you filter by direction, byte pattern, or other criteria.

Rules are evaluated in order (first match wins). Each rule specifies an **action**:

- **Intercept** — hold the frame in the queue
- **Forward** — let the frame pass without stopping

When rules are present but none match a given frame, the frame is **auto-forwarded** (rules define an explicit allow-list for what to intercept).

### Managing Intercept Rules

=== "TUI"

    Tamper tab → Intercept Rules section → Add/Edit/Remove/Reorder

=== "Python API"

    ```python
    from protopoke.rules.rule import InterceptRule, RuleAction
    from protopoke.models import Direction

    # Intercept all client-to-server frames that start with 0x01
    rule = InterceptRule.create(
        label="Hold client login packets",
        pattern_str="01",
        action=RuleAction.INTERCEPT,
        direction=Direction.CLIENT_TO_SERVER,
    )
    api.add_intercept_rule(rule)

    # Auto-forward heartbeat frames (0xFF prefix) even when tamper is on
    skip = InterceptRule.create(
        label="Skip heartbeats",
        pattern_str="FF",
        action=RuleAction.FORWARD,
    )
    api.add_intercept_rule(skip)
    ```

=== "MCP"

    ```
    add_intercept_rule(name="Hold logins", pattern="01", direction="client_to_server", action="intercept")
    ```

## Replace Rules

Replace rules automatically rewrite byte patterns in frames as they flow through the proxy. They run **before** the intercept check and apply to traffic, forged frames, and tampered frames, depending on each rule's scope flags.

Rules are applied in order; later rules see the bytes already modified by earlier rules.

### Rule Types

| Type | Description |
|------|-------------|
| **Binary** | Match byte sequences using a human-readable hex pattern syntax with wildcards, ranges, and alternation |
| **Regex** | Match and replace using Python bytes-regex patterns with `\xNN` escapes and group backreferences |
| **Script** | Run a Python function that receives the raw frame bytes and a shared variable store, and returns modified bytes |

---

### Binary Rules

Binary rules use a space-separated hex pattern syntax that is compiled to a Python bytes regex internally.

#### Pattern Syntax

| Construct | Example | Meaning |
|-----------|---------|---------|
| Hex byte | `FF` | Match the exact byte `0xFF` (case-insensitive) |
| Wildcard | `??` | Match any single byte |
| Byte range | `[03-09]` | Match any byte in the range `0x03`–`0x09` (inclusive) |
| Exact repeat | `.{4}` | Match exactly 4 arbitrary bytes |
| Range repeat | `.{2,8}` | Match between 2 and 8 arbitrary bytes |
| Alternation | `(01\|02\|FF)` | Match any one of the listed bytes |
| Python escape | `\xNN` | Raw Python bytes-regex escape, passed through literally |
| Quantifier suffix | `??+`, `[03-09]*` | Standard `+` (one or more) and `*` (zero or more) quantifiers |
| Start anchor | `^` | Matches only at the beginning of the frame |
| End anchor | `$` | Matches only at the end of the frame |

Tokens are separated by whitespace; whitespace is ignored between tokens.

#### Examples

```
01 00 ??              matches 0x01 0x00 <any single byte>
FF [03-09] .{2}       matches 0xFF, one byte in 03–09, then 2 arbitrary bytes
(01|02) 00            matches (0x01 or 0x02) followed by 0x00
^ 01                  matches frames that start with 0x01
?? .{4} FF            matches any byte, 4 arbitrary bytes, then 0xFF
```

#### Python API

```python
from protopoke.rules.rule import ReplaceRule
from protopoke.models import Direction

# Replace every occurrence of 0x41 0x41 ("AA") with 0x42 0x42 ("BB")
rule = ReplaceRule.create(
    label="AA → BB",
    pattern_str="41 41",
    replacement=b"\x42\x42",
)
api.add_replace_rule(rule)

# Only rewrite client-to-server frames
rule = ReplaceRule.create(
    label="Strip client flag byte",
    pattern_str="01 ??",
    replacement=b"\x00\x00",
    direction=Direction.CLIENT_TO_SERVER,
)
api.add_replace_rule(rule)
```

---

### Regex Rules

Regex rules use standard Python bytes-regex patterns. `re.DOTALL` is always enabled so `.` matches `\x00`.

Pattern strings use `\xNN` escapes (e.g. `\x01\x00`) and support all Python regex metacharacters. Replacement strings support `\xNN` byte escapes and `\g<N>` group backreferences.

#### Python API

```python
rule = ReplaceRule.create(
    label="Uppercase ASCII range",
    rule_type="regex",
    pattern_str="",           # unused for regex rules
    replacement=b"",          # unused for regex rules
    regex_pattern=r"[\x61-\x7a]",   # a–z
    regex_replacement=r"\x41",      # replace with A (simplified example)
)
api.add_replace_rule(rule)

# Capture a two-byte length field and swap its bytes (big→little endian)
rule = ReplaceRule.create(
    label="Swap length bytes",
    rule_type="regex",
    pattern_str="",
    replacement=b"",
    regex_pattern=r"^([\x00-\xff])([\x00-\xff])",
    regex_replacement=r"\g<2>\g<1>",
)
api.add_replace_rule(rule)
```

---

### Script Rules

Script rules call a Python function you write, giving you full programmatic control over the transformation. This is the most powerful rule type: you can parse fields, maintain state across frames, extract values for later use in Forge playbooks, and implement any logic that binary/regex patterns cannot express.

#### The `apply()` Function

Your script must define a function with this exact signature:

```python
def apply(data: bytes, variables: dict) -> bytes:
    ...
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `bytes` | The raw frame bytes to transform |
| `variables` | `dict` | Shared global variable store (see below) |

The function must return `bytes` or `bytearray`. Returning anything else is treated as an error and the original frame is passed through unchanged.

**Minimal example** — XOR every byte with `0xAA`:

```python
def apply(data: bytes, variables: dict) -> bytes:
    return bytes(b ^ 0xAA for b in data)
```

#### Python API

```python
rule = ReplaceRule.create(
    label="XOR obfuscation",
    rule_type="script",
    pattern_str="",
    replacement=b"",
    script_path="/path/to/xor_rule.py",
)
api.add_replace_rule(rule)
```

---

#### The `variables` Store

The `variables` parameter is a **shared dictionary** that persists across every rule application in every pipeline (traffic, tamper, forge). All script rules in the same session share the same dict; mutations made by one rule are visible to all others immediately.

This lets you extract state from live traffic and use it in later frames or in Forge playbooks via `{{VARIABLE}}` placeholders.

**Example — capture a session token from the server's login response and reuse it in subsequent client frames:**

```python
# capture_token.py  (applied in traffic pipeline, SERVER_TO_CLIENT direction)
import struct

def apply(data: bytes, variables: dict) -> bytes:
    # Assume the server sends: 0x02 <4-byte token> ...
    if len(data) >= 5 and data[0] == 0x02:
        token = data[1:5].hex()
        variables["session_token"] = token
    return data  # pass through unchanged
```

```python
# inject_token.py  (applied in traffic pipeline, CLIENT_TO_SERVER direction)
import struct

def apply(data: bytes, variables: dict) -> bytes:
    token_hex = variables.get("session_token")
    if token_hex and len(data) >= 5:
        token_bytes = bytes.fromhex(token_hex)
        # Overwrite bytes 1–4 with the captured token
        return data[0:1] + token_bytes + data[5:]
    return data
```

**Example — increment a per-frame sequence counter:**

```python
# sequence_counter.py
def apply(data: bytes, variables: dict) -> bytes:
    seq = variables.get("seq", 0)
    variables["seq"] = seq + 1
    # Overwrite the first byte with the counter (mod 256)
    return bytes([seq & 0xFF]) + data[1:]
```

!!! tip "Using variables in Forge playbooks"
    Values stored in `variables` are also accessible as `{{VARIABLE_NAME}}` placeholders in Forge playbook frames. Store a key such as `variables["TOKEN"] = "abc123"` in a traffic-pipeline rule and it will be substituted automatically when the playbook sends its frames.

---

#### Module-Level State

Because the script is loaded as a Python module, any code at module level runs **once** when the rule is first applied. You can use this to initialise state that must survive between calls without polluting `variables`:

```python
# stateful_rule.py
import struct
from collections import defaultdict

_counters = defaultdict(int)  # module-level, not reset between frames

def apply(data: bytes, variables: dict) -> bytes:
    direction = variables.get("direction", "unknown")
    _counters[direction] += 1
    # Embed the count in bytes 0–3 (big-endian)
    count = _counters[direction]
    return struct.pack(">I", count) + data[4:]
```

Module-level state is **reset** when `reset_script_state()` is called (see below) or when the script raises an exception.

---

#### Error Handling and Auto-Reload

If your script raises an exception during `apply()`, ProtoPoke:

1. Logs the error (visible in the Logs tab).
2. **Clears the cached module** so the next frame reloads the script from disk.
3. Returns the original frame bytes unchanged.

This means you can fix a bug in the script file and the updated version is picked up automatically on the next frame — no need to restart the proxy or reload the rule.

The same auto-reload happens if the script file cannot be found or fails to import.

---

#### Resetting Script State

To force a reload of the script (discarding any module-level state) without waiting for an error:

```python
rule = api.get_replace_rule(rule_id)
rule.reset_script_state()
```

After this call, the next frame will re-execute all module-level code and reinitialise any module-level variables.

---

### Scope Flags

Each replace rule has three boolean flags that control which pipeline stages apply it:

| Flag | Default | Applies When |
|------|---------|--------------|
| `apply_to_traffic` | `True` | Every frame flowing through the proxy relay (before the tamper queue) |
| `apply_to_tamper` | `True` | Bytes modified by the operator in the Tamper tab, applied after **Modify + Forward** |
| `apply_to_forge` | `True` | Frames sent via the Forge tab or a playbook |

All three default to `True`. Set any to `False` to restrict the rule to specific pipelines:

```python
# Only rewrite traffic going through the relay; leave forge playbooks unmodified
rule = ReplaceRule.create(
    label="Strip debug flag",
    pattern_str="80",
    replacement=b"\x00",
    apply_to_forge=False,
)
api.add_replace_rule(rule)
```

=== "TUI"

    Edit a replace rule → expand the **Scope** section → toggle checkboxes

---

### Rule Ordering

Replace rules are applied in the order they appear in the list. Later rules see the bytes **already modified** by earlier rules. Order matters when one rule's output could match another rule's pattern.

```python
# r1 turns 0x41 into 0x42; r2 turns 0x42 into 0x43.
# With r1 first, 0x41 → 0x42 → 0x43.
# With r2 first, 0x41 is unchanged by r2, then 0x42 → 0x43... 0x41 stays 0x41.
engine.add_rule(ReplaceRule.create("r1", "41", b"\x42"))
engine.add_rule(ReplaceRule.create("r2", "42", b"\x43"))
```

Reorder rules in the TUI by dragging, or via the API:

```python
api.move_replace_rule(rule_id, new_index=0)
```

---

### Managing Replace Rules

=== "TUI"

    Tamper tab → Replace Rules section → Add/Edit/Remove/Reorder

=== "Python API"

    ```python
    from protopoke.rules.rule import ReplaceRule

    rule = ReplaceRule.create(
        label="Swap username",
        pattern_str="61 6C 69 63 65",   # "alice" in hex
        replacement=b"admin",
    )
    api.add_replace_rule(rule)
    ```

=== "MCP"

    ```
    add_replace_rule(name="Swap username", find_hex="616c696365", replace_hex="61646d696e")
    ```

## Direction and Session Filters

You can restrict tamper mode to specific directions or sessions:

=== "Python API"

    ```python
    from protopoke.models import Direction

    # Only intercept client-to-server traffic
    api.set_tamper_direction_filter(Direction.CLIENT_TO_SERVER)

    # Only intercept a specific session
    api.set_tamper_session_filter(session_id)
    ```

=== "MCP"

    ```
    tamper_set_direction_filter(direction="client_to_server")
    tamper_set_session_filter(session_id="<uuid>")
    ```
