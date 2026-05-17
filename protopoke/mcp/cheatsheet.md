# ProtoPoke MCP Tool Index

A map of every MCP tool the ProtoPoke server exposes, grouped by concern.
Use this to discover what's available; call the individual tools to get
their full docstring and argument schema.

Related resources:

- `protopoke://guides` — authoring guides (framers, protocol definitions,
  script replace rules). Read these before writing extension code.
- `protopoke://recipes` — end-to-end workflows that chain several tools
  together (reverse-engineer an unknown protocol, replay with mutation,
  intercept and rewrite).

## Proxy lifecycle

- `proxy_status` — running forwarders, session and tamper counts.
- `proxy_start` / `proxy_stop` — start or stop every configured forwarder.

## Forwarder management

- `list_forwarders` — every configured forwarder and its state.
- `add_forwarder` / `remove_forwarder` — add or delete a forwarder.
- `start_forwarder` / `stop_forwarder` — toggle a single forwarder.
- `update_forwarder` — change the listen/upstream address.
- `update_forwarder_config` — hot-swap name, framer, or protocol on a
  running forwarder without restarting it.

## Session management

- `list_sessions` — every session ever opened (open + closed).
- `get_session` / `get_session_summary` — details for one session.
- `get_frames` / `get_frame` — raw captured frames.
- `decode_frames` / `decode_frame_by_id` — frames parsed against the
  currently loaded protocol definition.
- `search_frames` — find frames by hex / text substring.
- `terminate_session` — close the live connection.
- `delete_session` — drop a session from the registry.
- `export_session` — dump a session as JSON.

## Protocol management (read-only)

- `get_protocol_info` — name + flags for the currently loaded protocol.
- `get_protocol_definition` — full active definition as a YAML-compatible
  dict (or `{"error": ...}` if no definition is loaded).
- `get_protocol_definition_schema` — the YAML schema spec for ProtocolDefinition
  files.  Use this when the operator asks you to draft a definition from
  what you've learned — emit YAML in chat for them to paste/load
  manually.  ProtoPoke does not expose any MCP write path for protocol
  definitions.

## Knowledge base (cross-session AI memory)

Findings and notes persisted in the `.pp` project file.  Use this to
record reasoning that should survive across sessions instead of
re-deriving it every time.

- `list_findings` / `get_finding` / `add_finding` / `update_finding` /
  `remove_finding` — structured claims (hypothesis / confirmed /
  ruled_out / needs_review) with scope (protocol / message / field /
  byte range / forwarder), evidence frame IDs, and tags.
- `list_notes` / `get_note` / `add_note` / `update_note` / `remove_note`
  — free-form markdown entries for context that doesn't fit a Finding.

The AI may only update/remove entries it authored AND that the user has
not locked from the TUI.  Refused mutations return an explanatory
error — add a counter-entry instead.

## Tamper control (intercept queue)

- `tamper_status` / `tamper_toggle` — global intercept on/off.
- `tamper_set_direction_filter` / `tamper_set_session_filter` — narrow
  what gets queued.
- `list_intercepted` — frames currently held.
- `tamper_decode_pending` — parse a pending frame against the protocol.
- `tamper_forward` / `tamper_drop` — release or discard one frame.
- `tamper_modify_and_forward` — release one frame with new bytes.
- `tamper_modify_field_and_forward` — release one frame with one parsed
  field edited.
- `tamper_forward_all` — flush the queue.

## Global replace rules

Applied to every frame on every session in real time. Mechanisms:
binary find/replace, regex, or Python script.

- `list_replace_rules` / `add_replace_rule` / `update_replace_rule` /
  `remove_replace_rule` / `reorder_replace_rule` / `clear_replace_rules`

For script rules see the `replace-scripts` authoring guide and
`get_script_load_instructions` for the operator hand-off.

## Intercept rules

Per-rule filters that auto-queue matching frames into the tamper queue.

- `list_intercept_rules` / `add_intercept_rule` / `update_intercept_rule` /
  `remove_intercept_rule` / `reorder_intercept_rule` /
  `clear_intercept_rules`

## Forge: send + inject

- `send_frame` — one-shot send to an arbitrary host:port.
- `open_forge_session` / `send_on_forge_session` — keep a forge socket
  open for multi-frame exchanges.
- `inject_to_server` / `inject_to_client` — push a frame into a live
  proxied session as if it came from the other side.

## Playbooks

Reusable scripted sequences of frames with `{{VARIABLE}}` substitution.

- `list_playbooks` / `create_playbook` / `get_playbook` /
  `update_playbook` / `delete_playbook`
- `run_playbook` — execute a playbook against a target.
- `frame_to_forge` — turn a captured frame into a playbook entry.

## Replay

- `forge_session` — replay every frame from one captured session.
- `replay_with_field_edits` — replay with named-field overrides.

## Framing

- `set_framer` — change the framer on a forwarder.
- `list_framers` — every registered framer.

## Variables

Shared `{{VARIABLE}}` table consumed by playbooks and forge replays.

- `get_variables` / `set_variable` / `delete_variable` / `clear_variables`

## TLS / CA

- `get_ca_cert` — fetch the on-disk MITM CA so the user can trust it.

## Fuzzing

- `fuzz_start` — kick off a campaign against a session with one or more
  mutators.
- `fuzz_status` / `fuzz_results` / `fuzz_stop`
- `list_campaigns` — every campaign ever run.
- `list_mutators` — available built-in mutators.

## Analysis (protocol reverse engineering)

Pure helpers over captured frames. Composable; see the
`reverse-engineer-unknown-protocol` recipe for a worked walkthrough.

- `list_field_types` — every supported field type for definitions.
- `get_frame_stats` — length / direction / entropy summary.
- `entropy_map` — Shannon entropy per byte offset, useful for finding
  random IDs, ciphertext, or compressed regions.
- `cluster_frames` — bucket frames by shape (length, leading bytes).
- `filter_frames` — slice the frame set by direction, length, content.
- `decode_field` — pull one field out of arbitrary bytes.
- `compare_frames` / `diff_frames_in_bucket` — byte-level diff.
- `analyze_byte_ranges` — per-offset value range across many frames.
- `find_length_fields` — candidate length-prefix offsets.
- `offset_correlations` — pairs of offsets whose values move together.

## Authoring guides (resources + tool fallbacks)

- `list_authoring_guides` / `get_authoring_guide` — fallback for clients
  that ignore MCP resources. Guides are also served as
  `protopoke://guides/<slug>`.
- `get_script_load_instructions` — operator-facing steps for loading a
  generated script rule into the UI.

## Workflow recipes (resources + tool fallbacks)

- `list_workflow_recipes` / `get_workflow_recipe` — fallback for clients
  that ignore MCP resources. Recipes are also served as
  `protopoke://recipes/<slug>`.
