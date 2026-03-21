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

### Managing Rules

=== "TUI"

    Tamper tab → Intercept Rules section → Add/Edit/Remove/Reorder

=== "Python API"

    ```python
    from protopoke.rules.rule import InterceptRule, RuleAction
    from protopoke.models import Direction

    rule = InterceptRule(
        name="Hold client login packets",
        pattern=b"\x01",
        direction=Direction.CLIENT_TO_SERVER,
        action=RuleAction.INTERCEPT,
    )
    api.add_intercept_rule(rule)
    ```

=== "MCP"

    ```
    add_intercept_rule(name="Hold logins", pattern="01", direction="client_to_server", action="intercept")
    ```

## Replace Rules

Replace rules automatically rewrite byte patterns in frames as they pass through the relay. They apply to all traffic (proxied, forged, and replayed) and run **before** the intercept check.

Each replace rule has:

- A **find** pattern (binary bytes or regex)
- A **replace** value
- An optional **direction** filter
- An **enabled** flag

Replace rules are also evaluated in order.

### Rule Types

| Type | Description |
|------|-------------|
| **Binary** | Find and replace exact byte sequences |
| **Regex** | Match and replace using regular expressions |
| **Script** | Run a Python function that receives the frame bytes and returns modified bytes |

### Managing Replace Rules

=== "TUI"

    Tamper tab → Replace Rules section → Add/Edit/Remove/Reorder

=== "Python API"

    ```python
    from protopoke.rules.rule import ReplaceRule

    rule = ReplaceRule(
        name="Swap username",
        find=b"alice",
        replace=b"admin",
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
