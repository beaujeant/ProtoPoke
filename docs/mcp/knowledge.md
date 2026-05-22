---
title: "Knowledge Base"
---

ProtoPoke ships a project-scoped knowledge base for **cross-session AI
memory**.  An AI client (over MCP) and a human operator (via the Notes
tab in the TUI) can read and write two kinds of entries that travel
inside the `.pp` project file:

- **Findings** — structured claims about the protocol under
  investigation: hypotheses, confirmed facts, ruled-out theories, with
  scope (protocol / message / field / byte range / forwarder),
  evidence frame IDs, status, and confidence.
- **Notes** — free-form markdown entries for context that does not fit
  the Finding shape (open questions, design hypotheses about the whole
  protocol, test-setup reminders).

The point is to stop the AI from re-deriving everything from scratch
on every session.  On session start, call `list_findings` and
`list_notes` to recover what previous sessions established before
re-running the analysis tools.

`list_findings` and `list_notes` return **compact rows** to keep the
session-start recovery cheap: long descriptions / note bodies are
previewed (with a `description_truncated` / `body_truncated` flag),
evidence frame-ID lists are given as `evidence_frame_count` /
`counter_evidence_frame_count`, and null scope fields are omitted. Call
`get_finding(id)` / `get_note(id)` for the complete record — full text
and the full evidence frame-ID lists.

## Why "AI as advisor"

The knowledge base is deliberately additive.  The MCP layer **does
not** expose any tool to load, edit, or save the active
`ProtocolDefinition` — that authority stays with the operator.  When
the AI has enough evidence to draft a definition it emits the YAML in
chat (see `get_protocol_definition_schema` for the spec), and the
operator reviews, saves, and loads it manually.

The same principle holds for findings and notes the user has reviewed:
mutations from the Notes tab set `locked=True` on the entry, and the
MCP layer refuses subsequent AI updates or deletes on locked entries
or on entries the AI did not author.  The AI's only recourse in
that case is to add a **counter-finding** explaining the disagreement.

## Finding schema

| Field | Type | Notes |
|-------|------|-------|
| `id` | string (UUID) | Stable identifier — never changes |
| `created_at` / `updated_at` | float (epoch seconds) | Set by the store |
| `author` | string | `"ai"` for MCP adds, `"user"` for TUI adds |
| `locked` | bool | True once the user has mutated the entry — MCP refuses further AI mutations |
| `protocol_name` | string \| null | Optional scope |
| `message_name` | string \| null | Optional scope (message type) |
| `field_name` | string \| null | Optional scope (field within a message) |
| `byte_offset` / `byte_length` | int \| null | Pin to a raw byte range when no field exists yet |
| `direction` | `client_to_server` \| `server_to_client` \| null | Optional |
| `forwarder_id` | string \| null | Stable forwarder UUID — survives renames; the current `forwarder_name` is resolved into the MCP response |
| `title` | string | One-line summary (required) |
| `description` | string | Markdown body |
| `status` | `hypothesis` \| `confirmed` \| `ruled_out` \| `needs_review` | Lifecycle state |
| `confidence` | `low` \| `medium` \| `high` | |
| `evidence_frame_ids` | list[string] | Frame IDs that support the claim |
| `counter_evidence_frame_ids` | list[string] | Frames that would refute it |
| `tags` | list[string] | Free-form filtering |

## Note schema

| Field | Type | Notes |
|-------|------|-------|
| `id`, `created_at`, `updated_at`, `author`, `locked` | — | Same semantics as Finding |
| `title` | string | One-line label |
| `body_md` | string | Markdown body |
| `tags` | list[string] | Free-form filtering |

## MCP tools

```text
# Findings
list_findings(query=None, status=None, author=None,
              protocol_name=None, message_name=None, field_name=None,
              forwarder_id=None, tags=None)
get_finding(finding_id)
add_finding(title, description="", status="hypothesis",
            confidence="medium",
            protocol_name=None, message_name=None, field_name=None,
            byte_offset=None, byte_length=None,
            direction=None, forwarder_id=None,
            evidence_frame_ids=None, counter_evidence_frame_ids=None,
            tags=None)
update_finding(finding_id, ...)   # any subset of the add_finding kwargs
remove_finding(finding_id)

# Notes
list_notes(query=None, author=None, tags=None)
get_note(note_id)
add_note(title, body_md="", tags=None)
update_note(note_id, title=None, body_md=None, tags=None)
remove_note(note_id)
```

## Worked example

The AI clusters frames and notices that bytes 4-5 of `LoginRequest`
are always different by exactly the bit-flip pattern characteristic of
a CRC.  It records the hypothesis:

```text
add_finding(
    title="bytes 4-5 of LoginRequest look like a CRC16",
    description=(
        "Bytes vary across frames but the high bit of byte 4 never "
        "matches the high bit of any byte 0-3 — consistent with a "
        "checksum, inconsistent with a length."
    ),
    status="hypothesis", confidence="medium",
    message_name="LoginRequest",
    byte_offset=4, byte_length=2,
    evidence_frame_ids=["frame-id-1", "frame-id-2", "frame-id-3"],
    tags=["crc", "checksum"],
)
```

Then it uses tamper to flip a single bit in byte 4 of one such frame
and observes that the server rejects the request — confirming the
checksum hypothesis.  It promotes the finding:

```text
update_finding(finding_id="<the id returned above>",
               status="confirmed", confidence="high",
               description=description + "\n\nConfirmed by flipping "
                           "one bit in frame-id-1: server rejected.")
```

The operator reviews the finding in the Notes tab, marks it as
correct, and saves the project.  The Notes-tab save flips `locked` to
True.  Next session, the AI calls `list_findings(message_name="LoginRequest")`
and immediately sees the confirmed CRC16 location plus the operator's
sign-off.  It can build on top of the finding (e.g. propose the right
polynomial) but cannot silently rewrite it.

## Persistence

Both lists are saved as plain JSON members in the `.pp` archive:

```
findings.json
notes.json
```

See the [Project File reference](/core/getting-started) for the full
archive layout.
