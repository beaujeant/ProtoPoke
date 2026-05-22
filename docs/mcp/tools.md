---
title: "MCP Tool Reference"
---

ProtoPoke exposes 90+ tools through MCP. All tools return JSON-serialisable dicts; bytes fields are hex-encoded strings.

## Discovery Resources

In addition to the tools listed below, the MCP server exposes a handful
of markdown documents as resources for client-side discovery. Clients
without a resource browser can read the same content through the tool
fallbacks shown in each section.

| Resource URI | Purpose |
|--------------|---------|
| `protopoke://tools` | Curated cheat-sheet of every MCP tool grouped by concern (no tool fallback — use the `list_*` tools below for programmatic discovery) |
| `protopoke://guides` | Index of authoring guides (one per extension point) |
| `protopoke://guides/<slug>` | One authoring guide (`framers`, `protocol-definitions`, `replace-scripts`) |
| `protopoke://recipes` | Index of end-to-end workflow recipes |
| `protopoke://recipes/<slug>` | One recipe (`reverse-engineer-unknown-protocol`, `replay-with-mutation`, `intercept-and-rewrite`, `validate-with-tamper`, `map-state-machine`) |

## Authoring Guides

Short reference documents shipped with the MCP server. Each guide explains
how to write one of ProtoPoke's extension points (custom framer, protocol
definition YAML, custom replace script) and is suitable to read before
generating one. The same content is also exposed as MCP resources at
`protopoke://guides` and `protopoke://guides/<slug>` for clients that
surface resources in a picker.

| Tool | Description |
|------|-------------|
| `list_authoring_guides` | List available guides (`framers`, `protocol-definitions`, `replace-scripts`) with their resource URIs |
| `get_authoring_guide` | Return the markdown body of one guide by slug |
| `get_script_load_instructions` | Return the operator-facing click-path for loading a generated script as a replace rule (script rules cannot be persisted over MCP — the user must accept the code) |

## Workflow Recipes

End-to-end task walkthroughs that chain several MCP tools together.
Where authoring guides describe a single extension point, recipes
describe a complete job. Also exposed as MCP resources at
`protopoke://recipes` and `protopoke://recipes/<slug>`.

| Tool | Description |
|------|-------------|
| `list_workflow_recipes` | List available recipes (`reverse-engineer-unknown-protocol`, `replay-with-mutation`, `intercept-and-rewrite`, `validate-with-tamper`, `map-state-machine`) with their resource URIs |
| `get_workflow_recipe` | Return the markdown body of one recipe by slug |

## Proxy Lifecycle

| Tool | Description |
|------|-------------|
| `proxy_status` | Running state, session counts, listen/upstream address |
| `proxy_start` | Start the proxy listener |
| `proxy_stop` | Stop the proxy and release resources |

## Forwarder Management

| Tool | Description |
|------|-------------|
| `list_forwarders` | All configured forwarders with status |
| `add_forwarder` | Add a new forwarder (TCP / UDP / SOCKS5) |
| `update_forwarder` | Update an existing forwarder's full configuration |
| `remove_forwarder` | Remove a forwarder by name |
| `start_forwarder` | Start a specific forwarder by name |
| `stop_forwarder` | Stop a specific forwarder by name |
| `update_forwarder_config` | Hot-swap name, framer, and/or protocol definition on a running forwarder |

## Session Management

| Tool | Description |
|------|-------------|
| `list_sessions` | All sessions (active + closed) with metadata |
| `get_session` | Details for one session by ID |
| `get_session_summary` | Frame counts, byte totals, duration, per-direction stats |
| `get_frames` | Raw frames for a session (hex-encoded), with optional direction filter |
| `get_frame` | One specific frame by session ID + frame ID |
| `decode_frames` | All frames decoded using the loaded protocol decoder |
| `decode_frame_by_id` | Decode one specific frame into named, typed fields |
| `search_frames` | Binary pattern search across all (or one) session(s) |
| `terminate_session` | Close an active session |
| `delete_session` | Remove a session from the registry |
| `export_session` | Export a session's data |

## Protocol Management (read-only)

The MCP surface for protocol definitions is intentionally read-only: the
operator is the only party who can load, edit, or save a definition.
When the AI wants to propose a new or updated definition it should emit
the YAML in chat and ask the operator to save and load it (via the TUI
or by pointing a `ForwarderConfig.protocol_definition_path` at the
file).

| Tool | Description |
|------|-------------|
| `get_protocol_info` | Currently loaded decoder/encoder names and status |
| `get_protocol_definition` | The active definition as a YAML-compatible dict (or `{"error": ...}` if none is loaded) |
| `get_protocol_definition_schema` | The authoritative YAML schema spec for `ProtocolDefinition` files, with a worked example. Use this when composing a definition in chat |

## Knowledge Base (cross-session AI memory)

Persistent findings and notes stored in the `.pp` project file.  Use
this to record reasoning that should survive across AI sessions
instead of re-deriving everything every time.  Findings are
structured (status, confidence, scope, evidence frame IDs); notes are
free-form markdown.  See the [Knowledge Base guide](/mcp/knowledge)
for the schema and a worked example.

The AI may only update or remove entries it authored AND that the
user has not locked from the TUI.  Refused mutations return an
explanatory error — add a counter-entry instead.

| Tool | Description |
|------|-------------|
| `list_findings` | Findings filtered by query / status / author / scope / tags |
| `get_finding` | One finding by ID (with the current `forwarder_name` resolved from `forwarder_id`) |
| `add_finding` | Record a new finding (always `author="ai"`, `locked=false`) |
| `update_finding` | Update one or more fields of an AI-authored unlocked finding |
| `remove_finding` | Remove an AI-authored unlocked finding |
| `list_notes` | Notes filtered by query / author / tags |
| `get_note` | One note by ID |
| `add_note` | Record a new free-form markdown note |
| `update_note` | Update an AI-authored unlocked note |
| `remove_note` | Remove an AI-authored unlocked note |

## Tamper Control

| Tool | Description |
|------|-------------|
| `tamper_status` | Enabled flag, queue depth, active filters |
| `tamper_toggle` | Enable or disable tampering |
| `list_intercepted` | All frames currently waiting for a verdict |
| `tamper_decode_pending` | Pending frames with their parsed protocol view |
| `tamper_forward` | Forward a frame as-is |
| `tamper_drop` | Drop a frame (do not forward) |
| `tamper_modify_and_forward` | Replace payload bytes and forward |
| `tamper_modify_field_and_forward` | Edit named protocol fields and forward (auto-recomputes lengths) |
| `tamper_forward_all` | Forward all pending frames at once |
| `tamper_set_direction_filter` | Restrict tampering to one direction |
| `tamper_set_session_filter` | Restrict tampering to specific sessions |

## Replace Rules

| Tool | Description |
|------|-------------|
| `list_replace_rules` | All replace rules in evaluation order |
| `add_replace_rule` | Add a binary find-and-replace rule |
| `update_replace_rule` | Toggle enabled state or rename a rule |
| `remove_replace_rule` | Remove a rule by ID |
| `reorder_replace_rule` | Move a rule to a different position |
| `clear_replace_rules` | Remove all replace rules |

## Intercept Rules

| Tool | Description |
|------|-------------|
| `list_intercept_rules` | All intercept rules in evaluation order |
| `add_intercept_rule` | Add a filter rule (intercept or forward action) |
| `update_intercept_rule` | Toggle, rename, or change action of a rule |
| `remove_intercept_rule` | Remove a rule by ID |
| `reorder_intercept_rule` | Move a rule to a different priority position |
| `clear_intercept_rules` | Remove all intercept rules |

## Forge / Direct Send

| Tool | Description |
|------|-------------|
| `send_frame` | One-shot send of raw bytes to host:port |
| `open_forge_session` | Open a persistent TCP connection for repeated sends |
| `send_on_forge_session` | Send data on an open forge session |
| `inject_to_server` | Inject a frame to the upstream on a live proxy session |
| `inject_to_client` | Inject a frame to the client on a live proxy session |

## Playbook Management

| Tool | Description |
|------|-------------|
| `list_playbooks` | All saved playbooks |
| `create_playbook` | Create a new playbook with ordered frames |
| `get_playbook` | Get a playbook by ID |
| `update_playbook` | Modify a playbook |
| `delete_playbook` | Remove a playbook |
| `run_playbook` | Execute a playbook against a target |
| `frame_to_forge` | Create a playbook entry from a captured frame |

## Replay

| Tool | Description |
|------|-------------|
| `forge_session` | Re-send a session's frames to the server |
| `replay_with_field_edits` | Replay with per-message-type field overrides |

## Framing

| Tool | Description |
|------|-------------|
| `list_framers` | List the available built-in framers and their parameters |
| `set_framer` | Hot-swap the active framer on all running sessions without restart |

## Variables

| Tool | Description |
|------|-------------|
| `get_variables` | Get the current variable store |
| `set_variable` | Set a variable value |
| `delete_variable` | Remove a single variable |
| `clear_variables` | Clear all variables |

## TLS / CA

| Tool | Description |
|------|-------------|
| `get_ca_cert` | Export the CA certificate PEM |

## Analysis

Protocol-agnostic analytical helpers for reverse engineering. Every tool
operates on the frames already captured in a session — no I/O, no
configuration changes. Most analysis tools accept the same scoping
parameters (`direction`, `size_bytes`, `byte_patterns`) so you can focus on
one packet type at a time. See the [Protocol Reversing guide](/mcp/analysis)
for the typical workflow.

| Tool | Description |
|------|-------------|
| `list_field_types` | Every type name accepted by `decode_field` and `offset_correlations` |
| `get_frame_stats` | Bucket frames by `(prefix, size)`, with per-offset change rate and Shannon entropy per bucket |
| `entropy_map` | Per-offset entropy across a same-size bucket — find constant padding vs encrypted regions |
| `cluster_frames` | Auto-discover packet-type clusters by `(prefix, size)` |
| `filter_frames` | Paginated direction / size / byte-pattern filter — replaces dumping everything to disk |
| `decode_field` | Decode `bytes[offset:offset+size]` as a given type across frames; `deduplicate=True` only emits rows when the value changes |
| `compare_frames` | Byte-level diff between two specific frames, with coalesced ranges and integer delta |
| `diff_frames_in_bucket` | Column-by-column diff matrix across same-size frames — surfaces which offsets carry information |
| `analyze_byte_ranges` | Per-offset + per-range heuristics: candidate types, constant/ASCII/counter/length flags |
| `find_length_fields` | Offsets whose value tracks frame length (`value == len(frame) - C`), works across mixed-size frames |
| `offset_correlations` | Pearson correlation and change-pairing between two offsets |
| `find_constant_byte_sequences` | Recurring byte n-grams that appear in ≥X% of frames regardless of offset — magic markers, version stamps, trailers |
| `align_frames` | Needleman-Wunsch global alignment of mixed-size frames against the first frame — draws field boundaries when prefixes shift |
| `extract_strings` | `strings(1)` for captured frames — printable-ASCII (and optionally UTF-16-LE) runs of length ≥ N |
| `detect_tlv` | Try Type-Length-Value layouts (T width 1/2, L width 1/2/4, BE/LE, length-includes-header) and score completion per shape |
| `detect_checksums_crcs` | Try sum8/xor8/sum16/fletcher16/CRC-16-CCITT/CRC-16-XMODEM/CRC-32-IEEE/Adler-32 against every offset and report matches |
| `detect_timestamps` | Offsets whose uint32/uint64 value lies in a plausible epoch range (unix sec/ms, NTP, Windows FILETIME), ranked by correlation with capture time |
| `detect_compression_encryption` | Per-frame magic-signature scan (gzip, zlib, lz4, zstd, PNG, JPEG, ZIP, ELF, PE, ASN.1, TLS records, SSH banners, …) plus high-entropy windows |
| `echo_detection` | Find values sent in one direction that reappear at a fixed offset in the opposite direction — transaction IDs, session tokens |
| `analyze_field_correlation` | Decode one `(byte_offset, byte_length, encoding)` field as a time series across frames (`frame_id`, `timestamp`, `sequence_number`, `value`) |
| `bruteforce_numeric_layout` | Score every encoding at every offset on a sample of the dominant size bucket — float validity, high-byte stability, smoothness/monotonicity — and return the top candidates |
| `group_by_field_value` | Bucket frames by the concatenated value at one or more `(offset, length)` ranges — flag fields and joint distributions across offsets |
| `diff_frames` | Per-byte diff of two frames plus decoded deltas for declared `(offset, length, encoding)` fields |
| `bisect_field_meaning` | Sweep a field across candidate values over a live forge session and capture each server response — confirm meaning by observation |
| `export_session_csv` | Flatten a session to CSV given declared fields (`name`, `byte_offset`, `byte_length`, `encoding`, optional `message_filter`) |
| `detect_periodic_streams` | Flag `(prefix, size)` buckets with periodic inter-arrival times (mean/std/cv, `is_periodic`) — heartbeats, pings, keepalives |

### Compact encodings for the field-bruteforce / time-series tools

`analyze_field_correlation`, `bruteforce_numeric_layout`,
`group_by_field_value`, `diff_frames`, `bisect_field_meaning`, and
`export_session_csv` use short encoding names (distinct from the
`decode_field` type list): `u8`, `i8`, `u16_le`, `u16_be`, `i16_le`, `i16_be`,
`u32_le`, `u32_be`, `i32_le`, `i32_be`, `f32_le`, `f32_be`, `f64_le`,
`f64_be`. Any `byte_length` argument must match the encoding width.

### Field types for `decode_field` / `offset_correlations`

Numeric types come in explicit endianness variants (`uint16_le`, `float32_be`,
…). Use `list_field_types` for the full live list. Non-numeric helpers
accepted by `decode_field`:

| Name | Behaviour |
|------|-----------|
| `ascii` | Bytes rendered as printable ASCII with `.` for non-printables |
| `bytes` | Raw bytes as a hex string |
| `cstring` | Bytes up to the first NUL, decoded as UTF-8 |
