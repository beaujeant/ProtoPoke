---
title: "MCP Tool Reference"
---

ProtoPoke exposes 70+ tools through MCP. All tools return JSON-serialisable dicts; bytes fields are hex-encoded strings.

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

## Protocol Management

| Tool | Description |
|------|-------------|
| `set_protocol_file` | Load a YAML/JSON protocol definition file |
| `set_protocol_dict` | Load a protocol definition from an inline dict |
| `get_protocol_info` | Currently loaded decoder/encoder names and status |

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

## Fuzzing

| Tool | Description |
|------|-------------|
| `list_mutators` | List the available mutators and their parameters |
| `fuzz_start` | Start a fuzzing campaign (runs in background) |
| `fuzz_status` | Poll campaign progress |
| `fuzz_results` | Fetch results (optionally only interesting ones) |
| `fuzz_stop` | Stop a running campaign |
| `list_campaigns` | List all campaigns |

### Mutator Names for `fuzz_start`

| Name | Parameters | Requires protocol definition |
|------|------------|------------------------------|
| `bit_flip` | `count` (default: 1) | No |
| `byte_insert` | `count` (default: 4) | No |
| `byte_delete` | `max_count` (default: 4) | No |
| `known_bad` | — | No |
| `radamsa` | `radamsa_path`, `timeout` (default: 5.0) | No |
| `field_boundary` | — | Yes |
| `field_overflow` | `lengths` (default: [256, 1024, 4096]) | Yes |
| `null_byte` | — | Yes |
| `length_mangle` | — | Yes |
