---
title: "Notes"
---

The **Notes** tab (`F6`) is the project's knowledge base — structured
findings and free-form notes that travel with the `.pp` project file
and persist across both your TUI sessions and any AI session connected
via MCP.

Use it as the place to record what you've learned about a protocol so
you (and the next AI session) don't have to re-derive it.

## Findings vs Notes

A **Finding** is a structured claim about the protocol you're
reversing.  It carries scope (protocol / message / field / byte range
/ forwarder), a status (`hypothesis` / `confirmed` / `ruled_out` /
`needs_review`), a confidence level, and evidence frame IDs.  Use it
for anything you'd want filterable: "bytes 4-5 of LoginRequest are a
CRC16 (confirmed, high)" or "the third byte of every server reply is
*not* a length prefix (ruled out)".

A **Note** is a free-form markdown entry for anything that doesn't fit
the Finding shape: open questions, design hypotheses about the whole
protocol, reminders about your test harness, links to vendor docs.

## Authorship and locking

Every entry carries an `author` ("ai" or "user") and a `locked` flag.
The rules are:

- Entries created in the TUI start as `author="user"` and `locked=True`.
- Entries created over MCP by the AI start as `author="ai"` and
  `locked=False`.
- **Saving any change from the TUI flips `locked=True`** on the
  entry, regardless of who originally authored it.  This is how you
  "take ownership" — once locked, the MCP layer refuses any further
  AI mutation.
- The AI can still add **new** entries (including counter-findings
  that disagree with yours) — it just can't silently change yours.

This keeps you in the loop: the AI can populate the knowledge base
freely, you review and lock what's correct, and the AI's only
recourse on locked entries is to add a counter-finding that you
review in turn.

## Layout

A horizontal toolbar at the top toggles between the **Findings** and
**Notes** sub-views (single segmented control).  Each sub-view has:

- A free-text filter input that matches against title, body, and tags.
- **+ New** — open the editor modal for a new entry.
- **Edit** — edit the highlighted entry.
- **Delete** — confirm-then-remove the highlighted entry.

Below the toolbar is a table of entries:

- **Findings:** status, confidence, scope summary, title, author,
  locked-flag.
- **Notes:** title, tags, author, locked-flag, last-updated timestamp.

Selecting a row populates the **details pane** at the bottom of the
tab with the full content (description / body markdown plus every
scope field).

## Persistence

Knowledge-base entries are saved alongside the rest of the project
state when you save the `.pp` file (`Ctrl+S` / `Alt+S`).  Two
new JSON members appear in the ZIP:

- `findings.json`
- `notes.json`

When you open a project, both lists are loaded into the
`KnowledgeBase` that the MCP server shares with the TUI, so any
already-connected AI client immediately sees the new content.
