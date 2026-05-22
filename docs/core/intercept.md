---
title: "Intercept"
---

The tamper system has two parts: the **intercept queue** (frames paused for
a manual verdict) and the **rules engine** (intercept rules that decide what
to hold, and replace rules that rewrite bytes automatically).

## The intercept queue

Enable tamper mode, then drive the queue:

```python
api.tamper_enabled = True

unit = await api.get_next_intercepted()      # blocks for the next frame
print(unit.frame.direction, unit.frame.raw_bytes.hex())

api.forward(unit.id)                          # send unchanged
api.drop(unit.id)                             # discard
api.modify_and_forward(unit.id, new_bytes=b"\x01\x02\x03")
```

Inspect the queue without consuming it:

```python
pending = api.list_intercepted()
count   = api.pending_count()
api.forward_all()                             # release everything pending
```

With a protocol definition loaded you can intercept *and parse* in one call,
then edit named fields (length fields are recomputed automatically):

```python
unit, parsed = await api.get_next_intercepted_parsed()
if parsed and parsed.message_type == "LoginRequest":
    api.modify_field_and_forward(unit.id, {"username": "admin"})
else:
    api.forward(unit.id)
```

### Direction and session filters

```python
from protopoke.models import Direction

api.tamper_direction_filter = Direction.CLIENT_TO_SERVER   # only C->S
api.tamper_session_filter   = {session_id}                 # only these sessions

api.tamper_direction_filter = None                         # clear
api.tamper_session_filter   = None
```

## Intercept rules

Intercept rules form an explicit allow-list of *which* frames to hold. They
are evaluated in order, first match wins; if rules exist but none match, the
frame is auto-forwarded.

```python
from protopoke.rules.rule import InterceptRule, RuleAction
from protopoke.models import Direction

# Hold client login packets (start with 0x01)
api.add_intercept_rule(InterceptRule.create(
    label="Hold client logins",
    pattern_str="01",
    action=RuleAction.INTERCEPT,
    direction=Direction.CLIENT_TO_SERVER,
))

# Let heartbeats pass without stopping
api.add_intercept_rule(InterceptRule.create(
    label="Skip heartbeats",
    pattern_str="FF",
    action=RuleAction.FORWARD,
))

api.list_intercept_rules()
api.remove_intercept_rule(rule_id)
```

## Replace rules

Replace rules rewrite byte patterns automatically, *before* the intercept
check. They run in order — a later rule sees the bytes already modified by
earlier ones — and their **scope** flags (`apply_to_traffic`,
`apply_to_tamper`, `apply_to_forge`, all `True` by default) decide which
pipelines they touch.

### Binary rules

A readable hex pattern syntax: `??` wildcard, `[03-09]` ranges, `.{2,8}`
repeats, `(01|02)` alternation, `^`/`$` anchors.

```python
from protopoke.rules.rule import ReplaceRule
from protopoke.models import Direction

api.add_replace_rule(ReplaceRule.create(
    label="AA -> BB",
    pattern_str="41 41",
    replacement=b"\x42\x42",
))

# Restrict to one direction and one pipeline
api.add_replace_rule(ReplaceRule.create(
    label="Strip debug flag",
    pattern_str="80",
    replacement=b"\x00",
    direction=Direction.CLIENT_TO_SERVER,
    apply_to_forge=False,
))
```

### Regex rules

Standard Python bytes-regex with `\xNN` escapes and `\g<N>` backreferences;
`re.DOTALL` is always on.

```python
api.add_replace_rule(ReplaceRule.create(
    label="Swap length bytes (big -> little)",
    rule_type="regex",
    pattern_str="",
    replacement=b"",
    regex_pattern=r"^([\x00-\xff])([\x00-\xff])",
    regex_replacement=r"\g<2>\g<1>",
))
```

### Script rules

The most powerful type — a Python function you write, with full access to
parse fields, keep state, and stash values for Forge.

```python
api.add_replace_rule(ReplaceRule.create(
    label="DNS A -> 127.0.0.1",
    rule_type="script",
    pattern_str="",
    replacement=b"",
    script_path="examples/scripts/dns_a_to_localhost.py",
))
```

The `apply(data, variables)` contract, the shared `variables` store,
module-level state, and auto-reload are documented in
[Custom Replace Scripts](/reference/replace-scripts).

### Managing rules

```python
api.list_replace_rules()
api.remove_replace_rule(rule_id)
api.rules_engine.move_rule(rule_id, new_index=0)   # reorder
```

## Next

- [Custom Replace Scripts](/reference/replace-scripts)
- [Forge](/core/forge) — send, replay, playbooks
- [User Interface — Intercept](/ui/intercept) — the same, in the TUI
