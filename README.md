# ProtoPoke

A personal TCP tamper and forge tool — think Burp Suite for arbitrary binary protocols.

Proxy any TCP connection, capture traffic in both directions, pause and inspect frames, modify or drop them live, and forge/replay captured sessions against a server. Load a YAML protocol definition and frames are automatically decoded into named fields with a Wireshark-style hex + tree view, and you can edit individual fields by name during intercept or replay.

This is a personal security research tool. It prioritises **readability, extensibility, and hackability** over throughput.

---

## Features

- **Transparent TCP proxy** — listens locally, forwards to any upstream host/port
- **TLS/SSL MITM** — auto-generates a root CA and per-session certificates (Burp-style); clients trust the CA once, proxy decrypts all sessions transparently
- **Multi-session** — handles many concurrent connections on one listener
- **Bidirectional capture** — every frame logged with direction, timestamp, sequence number
- **Intercept queue** — pause frames mid-stream, inspect, modify, forward, or drop
- **Intercept rules** — filter which frames get intercepted (by pattern, direction); first-match-wins ordered list
- **Global replace rules** — auto-rewrite byte patterns across relay, Forge, and Sequence pipelines
- **Three built-in framers** — raw (passthrough), delimiter (`\n`, `\r\n`, …), length-prefix (1/2/4/8 byte)
- **Forge** — hand-craft or modify frames and send them directly to the target; full send history
- **Project system** — save/load proxy config, intercept/replace rules, and forge requests to a JSON file
- **Protocol definition DSL** — describe any binary protocol in a YAML or JSON file; no code required
- **Protocol parser** — automatically decode frames into named, typed fields with offset and size metadata
- **Three match strategies** — identify packet types by magic bytes, by stream sequence position, or with a catch-all
- **Rich field types** — integers (u/int 8/16/32/64, float), raw bytes, strings (UTF-8/ASCII/UTF-16), bitfields, length-prefixed arrays, TLV sequences
- **Field-level tamper editing** — modify a single field by name, length fields auto-recomputed on encode
- **Field-level replay** — replay with per-message-type field edits, no manual frame ID tracking needed
- **Wireshark-style display** — hex dump with per-field ANSI colour highlights + nested field tree panel
- **Fuzzing** — replay-based fuzzing with a round-robin mutator pipeline; built-in raw mutators (bit-flip, byte insert/delete, known-bad payloads, radamsa) and protocol-aware mutators (field boundary values, overflow, null-byte injection, length mangling); automatic baseline capture and anomaly detection (crash, timeout, response size delta); extensible via a single-method `FrameMutator` ABC
- **Terminal UI (TUI)** — full Textual-based GUI: Config, Traffic, Tamper, Forge, and Fuzzer tabs
- **MCP server** — expose all proxy operations as AI tools via the Model Context Protocol (optional)
- **Event bus** — subscribe async handlers to session open/close and frame events
- **Pluggable storage** — in-memory default; SQLite backend interface ready for persistence

---

## Dependencies

### Runtime

| Package | Purpose |
|---|---|
| `cryptography >= 41` | TLS MITM: root CA generation, per-session certificate signing |
| `textual >= 0.80` | Terminal UI framework |
| `pyyaml` *(optional)* | Load protocol definitions from `.yaml` / `.yml` files. JSON files work without it. |
| `mcp >= 1.0` *(optional)* | MCP server (`pip install "protopoke[mcp]"`) |

The proxy core uses only the standard library. `cryptography` is only imported when `tls_listen=True` or `tls_upstream=True`. `pyyaml` is only imported when loading a YAML definition file.

### Development / testing

| Package | Purpose |
|---|---|
| `pytest >= 7.4` | Test runner |
| `pytest-asyncio >= 0.23` | asyncio test support |
| `pytest-cov >= 4.1` | Coverage reports |

---

## Installation

### uv (recommended)

```bash
# Clone the repo
git clone https://github.com/beaujeant/protopoke.git
cd protopoke

# Create venv and install with dev extras
uv venv
uv pip install -e ".[dev]"

# Run tests
uv run pytest
```

### venv + pip

```bash
git clone https://github.com/beaujeant/protopoke.git
cd protopoke

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pytest
```

To install with MCP support:

```bash
pip install -e ".[mcp]"
# or install everything:
pip install -e ".[all]"
```

> **Python 3.11+ required.**

---

## Running the TUI

After installation the `protopoke` command is available on your PATH:

```bash
protopoke
```

Or run directly:

```bash
python -m protopoke.ui.app
```

The TUI opens with five tabs:

| Tab | Key | Description |
|---|---|---|
| **Config** | F1 | Configure the listener, upstream server, TLS, framing, and protocol definition. Start/Stop the proxy. |
| **Traffic** | F2 | Live session list → frame list → hex/parsed detail view. Send any frame to Forge. |
| **Tamper** | F3 | View the intercept queue; forward, drop, or modify-and-forward individual frames. Manage ordered intercept rules and global replace rules. |
| **Forge** | F4 | Hand-craft frames in a hex editor and send them to the target; review the full send history. |
| **Fuzzer** | F5 | Select a captured session, pick mutators, run a campaign, and review results with crash/anomaly flags. |

### Keyboard shortcuts

| Key | Action |
|---|---|
| F1–F5 | Switch tabs |
| Ctrl+N | New project |
| Ctrl+O | Open project |
| Ctrl+S | Save project |
| Ctrl+Shift+S | Save project as… |
| Ctrl+Q | Quit |

### Project files

Projects save your proxy config, intercept/replace rules, and forge requests to a JSON file. Use **Ctrl+N** to start fresh, **Ctrl+O** to open an existing project, and **Ctrl+S** to save.

---

## MCP Server

ProtoPoke exposes all proxy operations as [Model Context Protocol](https://modelcontextprotocol.io/) tools. Once connected, an AI assistant can fully control the proxy — inspect sessions, tamper and modify frames live, forge/replay traffic with field edits, manage rules, and more — all through natural conversation.

### What the AI can do

| Capability | What you can ask |
|---|---|
| **Session inspection** | "List all sessions", "Show me the frames from session X", "How many bytes did the client send in session Y?", "Decode the frames and show me the field values" |
| **Live tamper** | "Enable tamper mode", "Show me the pending tampered frames", "Forward the first one but change the `username` field to `admin`", "Drop the frame that matches pattern `01 FF`" |
| **Rules** | "Add an intercept rule that holds all client→server frames starting with `0x01`", "Disable the replace rule named 'strip auth'", "Move the null-byte rule to position 0", "Clear all intercept rules" |
| **Search** | "Find all frames across all sessions that contain the bytes `FF FF 00`" |
| **Replay** | "Replay session X against `staging.internal:9090`", "Replay session X but change the `password` field to `hunter2` in every LoginRequest" |
| **Forge** | "Create a forge tab with the first frame from session X", "Send it and show me the response", "Change the payload to `deadbeef` and resend" |
| **Protocol decoding** | "Load the protocol definition from `myproto.yaml`", "Decode frame Y and explain what each field means" |
| **TLS** | "Give me the CA certificate so I can install it in my browser" |
| **Config** | "What port is the proxy listening on?", "Enable TLS on the upstream side" |

### Installation

```bash
pip install "protopoke[mcp]"
# or install everything at once:
pip install "protopoke[all]"
```

### Launching the MCP server

The MCP server starts the proxy and communicates with the AI client over **stdio** (standard MCP transport). Two ways to launch it:

**Dedicated command** (recommended):

```bash
protopoke-mcp \
  --upstream-host 10.0.0.1 \
  --upstream-port 9090 \
  --listen-port 8080
```

**Via the main command** with `--mcp`:

```bash
protopoke --mcp --upstream-host 10.0.0.1 --upstream-port 9090
```

**All CLI flags:**

| Flag | Default | Description |
|---|---|---|
| `--listen-host HOST` | `127.0.0.1` | Proxy bind address |
| `--listen-port PORT` | `8080` | Proxy listen port |
| `--upstream-host HOST` | `127.0.0.1` | Target host to forward to |
| `--upstream-port PORT` | `9090` | Target port to forward to |
| `--tamper` | off | Enable tamper mode on startup |
| `--tls-listen` | off | Terminate TLS on the client side (MITM mode) |
| `--tls-upstream` | off | Connect to upstream over TLS |
| `--no-tls-verify` | off | Accept any upstream TLS certificate |
| `--framer NAME` | `raw` | `raw`, `delimiter`, or `length_prefix` |
| `--protocol PATH` | — | Path to a `.yaml`/`.json` protocol definition |
| `--config PATH` | — | Load a saved ProxyConfig JSON file |
| `--log-level LEVEL` | `WARNING` | Python logging level; logs go to stderr |
| `--name NAME` | `ProtoPoke` | MCP server name shown to the AI client |

---

### Configuring Claude Desktop

Add a `protopoke` entry to your Claude Desktop MCP configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp",
      "args": [
        "--upstream-host", "10.0.0.1",
        "--upstream-port", "9090",
        "--listen-port",   "8080"
      ]
    }
  }
}
```

With TLS and a protocol definition:

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp",
      "args": [
        "--upstream-host", "api.example.com",
        "--upstream-port", "443",
        "--tls-listen",
        "--tls-upstream",
        "--protocol", "/path/to/myproto.yaml",
        "--tamper"
      ]
    }
  }
}
```

Restart Claude Desktop after editing. A hammer icon (🔨) will appear in the chat input bar when the server is connected. You can now ask Claude to interact with the proxy directly.

---

### Configuring Claude Code (this CLI)

Add ProtoPoke as an MCP server in your project's `.mcp.json` or `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "protopoke": {
      "command": "protopoke-mcp",
      "args": ["--upstream-host", "10.0.0.1", "--upstream-port", "9090"]
    }
  }
}
```

Or add it inline from the Claude Code CLI:

```bash
claude mcp add protopoke -- protopoke-mcp --upstream-host 10.0.0.1 --upstream-port 9090
```

---

### Configuring OpenAI (Agents SDK)

OpenAI's [Agents SDK](https://github.com/openai/openai-agents-python) has native MCP support via `MCPServerStdio`. Install it and connect to ProtoPoke:

```bash
pip install openai-agents "protopoke[mcp]"
```

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    # Spin up the ProtoPoke MCP server as a subprocess
    async with MCPServerStdio(
        name="ProtoPoke",
        params={
            "command": "protopoke-mcp",
            "args": [
                "--upstream-host", "10.0.0.1",
                "--upstream-port", "9090",
                "--listen-port",   "8080",
                "--tamper",
            ],
        },
    ) as mcp_server:
        agent = Agent(
            name="ProxyAnalyst",
            instructions=(
                "You are a security researcher analysing binary protocol traffic "
                "captured by a ProtoPoke proxy. Use the available tools to inspect "
                "sessions, decode frames, intercept and modify packets, and replay "
                "traffic as needed."
            ),
            mcp_servers=[mcp_server],
        )

        result = await Runner.run(
            agent,
            "List all captured sessions and decode the frames in the first one."
        )
        print(result.final_output)

asyncio.run(main())
```

The agent automatically discovers all ProtoPoke tools (list_sessions, get_frames, tamper_toggle, add_intercept_rule, forge_session, etc.) and can call them as needed.

---

### Programmatic usage (embed in your own script)

You can also build the MCP server directly in Python and run it alongside your own proxy automation:

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig
from protopoke.mcp.server import build_mcp_server

async def main():
    config = ProxyConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
        protocol_definition_path="myproto.yaml",
    )
    api = ProxyAPI(config)
    await api.start()

    mcp = build_mcp_server(api, name="ProtoPoke")
    await mcp.run_async()   # serves over stdio until the AI client disconnects

asyncio.run(main())
```

---

| Tool group | Tools |
|---|---|
| Proxy lifecycle | `proxy_status`, `proxy_start`, `proxy_stop` |
| Sessions | `list_sessions`, `get_session`, `get_frames`, `decode_frames` |
| Tamper | `tamper_status`, `tamper_toggle`, `list_intercepted`, `tamper_forward`, `tamper_drop`, `tamper_modify_and_forward` |
| Replace rules | `list_replace_rules`, `add_replace_rule`, `remove_replace_rule` |
| Intercept rules | `list_intercept_rules`, `add_intercept_rule`, `remove_intercept_rule` |
| Forge | `send_frame` |
| Replay | `replay_session` |
| Fuzzing | `fuzz_start`, `fuzz_status`, `fuzz_results`, `fuzz_stop`, `list_campaigns` |
| Config | `get_config`, `set_config` |
### Full tool reference

| Group | Tool | Description |
|---|---|---|
| **Proxy lifecycle** | `proxy_status` | Running state, session counts, listen/upstream address |
| | `proxy_start` | Start the proxy listener |
| | `proxy_stop` | Stop the proxy and release resources |
| **Sessions** | `list_sessions` | All sessions (active + closed) with metadata |
| | `get_session` | Details for one session by ID |
| | `get_session_summary` | Frame counts, byte totals, duration, per-direction stats |
| | `get_frames` | Raw frames for a session (hex-encoded), with optional direction filter |
| | `get_frame` | One specific frame by session ID + frame ID |
| | `decode_frames` | All frames decoded using the loaded protocol decoder |
| | `decode_frame_by_id` | Decode one specific frame into named, typed fields |
| | `search_frames` | Binary pattern search across all (or one) session(s) |
| **Tamper** | `tamper_status` | Enabled flag, queue depth, active filters |
| | `tamper_toggle` | Enable or disable tampering |
| | `list_intercepted` | All frames currently waiting for a verdict |
| | `tamper_decode_pending` | Pending frames with their parsed protocol view |
| | `tamper_forward` | Forward a frame as-is |
| | `tamper_drop` | Drop a frame (do not forward) |
| | `tamper_modify_and_forward` | Replace payload bytes and forward |
| | `tamper_modify_field_and_forward` | Edit named protocol fields and forward (auto-recomputes lengths) |
| | `tamper_forward_all` | Forward all pending frames at once |
| | `tamper_set_direction_filter` | Restrict tampering to one direction |
| | `tamper_set_session_filter` | Restrict tampering to specific sessions |
| **Replace rules** | `list_replace_rules` | All replace rules in evaluation order |
| | `add_replace_rule` | Add a binary find-and-replace rule |
| | `update_replace_rule` | Toggle enabled state or rename a rule |
| | `remove_replace_rule` | Remove a rule by ID |
| | `reorder_replace_rule` | Move a rule to a different position |
| | `clear_replace_rules` | Remove all replace rules |
| **Intercept rules** | `list_intercept_rules` | All intercept rules in evaluation order |
| | `add_intercept_rule` | Add a filter rule (intercept or forward action) |
| | `update_intercept_rule` | Toggle, rename, or flip the action of a rule |
| | `remove_intercept_rule` | Remove a rule by ID |
| | `reorder_intercept_rule` | Move a rule to a different priority position |
| | `clear_intercept_rules` | Remove all intercept rules |
| **Protocol** | `set_protocol_file` | Load a YAML/JSON protocol definition file |
| | `set_protocol_dict` | Load a protocol definition from an inline dict |
| | `get_protocol_info` | Currently loaded decoder/encoder names and status |
| **Forge** | `send_frame` | One-shot send of raw bytes to host:port |
| | `list_forge_requests` | All named forge tabs |
| | `create_forge_request` | Create a new forge tab with a target and payload |
| | `get_forge_request` | Get a tab with its full send history |
| | `update_forge_request` | Change label, host, port, TLS, or payload |
| | `delete_forge_request` | Remove a tab and its history |
| | `send_forge_request` | Send the current payload and record the response |
| | `frame_to_forge` | Create a forge tab from a captured frame ("Send to Forge") |
| **Replay** | `replay_session` | Re-send a session's frames to the server |
| | `replay_with_field_edits` | Replay with per-message-type field overrides |
| **TLS / CA** | `get_ca_cert` | Export the CA certificate PEM for client trust store installation |
| **Config** | `get_config` | Current ProxyConfig as a JSON dict |
| | `set_config` | Update one or more config fields at runtime |

#### Fuzzing via MCP

Campaigns run as asyncio background tasks so the AI can start one and poll for results without blocking the MCP transport.

Mutators are specified as JSON objects — no Python objects needed:

```python
# The AI (or any MCP client) would call these tools in sequence:

# 1. Start a campaign
result = await mcp_client.call("fuzz_start", {
    "session_id": "<uuid>",
    "mutators": [
        {"name": "bit_flip"},
        {"name": "known_bad"},
        {"name": "field_overflow", "lengths": [256, 1024]},  # needs a protocol definition
    ],
    "iterations": 100,
    "stop_on_crash": True,
})
campaign_id = result["campaign_id"]   # e.g. "a3f9..."

# 2. Poll status
status = await mcp_client.call("fuzz_status", {"campaign_id": campaign_id})
# {"status": "running", "completed_iterations": 42, "crash_count": 0, ...}

# 3. Fetch interesting results only
findings = await mcp_client.call("fuzz_results", {
    "campaign_id": campaign_id,
    "interesting_only": True,
})

# 4. Stop early if needed
await mcp_client.call("fuzz_stop", {"campaign_id": campaign_id})

# 5. List all campaigns across the session
all_campaigns = await mcp_client.call("list_campaigns", {})
```

Available mutator names for `fuzz_start`:

| `name` | Parameters | Requires protocol definition |
|---|---|---|
| `bit_flip` | `count` (default 1) | No |
| `byte_insert` | `count` (default 4) | No |
| `byte_delete` | `max_count` (default 4) | No |
| `known_bad` | — | No |
| `radamsa` | `radamsa_path` (default `"radamsa"`), `timeout` (default 5.0) | No |
| `field_boundary` | — | Yes |
| `field_overflow` | `lengths` (default `[256, 1024, 4096]`) | Yes |
| `null_byte` | — | Yes |
| `length_mangle` | — | Yes |

---

## Usage (Python API)

### Step 1 — Frame the stream

TCP is a stream protocol. The OS delivers bytes in arbitrary chunks: a single `read()` may return half a message, one complete message, or three messages fused together. There is no built-in concept of "packet boundaries".

Before you can do anything meaningful — intercept, decode, replay — you need to cut that stream into discrete, atomic units called **frames**. That is the framer's job.

By default ProtoPoke uses the **raw framer**, which treats every `read()` chunk as one frame. This is fine for a first pass to observe traffic, but if the protocol sends multi-part messages or if the OS coalesces writes, frames will be partial or merged and the dissector will produce garbage.

**Your first task is always to identify the right framing strategy for your target protocol.**

#### Common framing patterns

| Protocol style | Framer | Example |
|---|---|---|
| Unknown / quick look | `raw` (default) | Any protocol, first look |
| Line-based text | `delimiter` with `\r\n` or `\n` | HTTP headers, SMTP, FTP |
| Null-terminated | `delimiter` with `\x00` | Many C-string protocols |
| Binary with length header | `length_prefix` | Most game/chat/custom binary protocols |
| Custom boundary logic | Custom script (`on_data` / `on_flush`) | Anything else |

#### How to pick and configure a framer

**Raw (default — no configuration needed):**
```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    # framer_name defaults to "raw"
)
```
Every `read()` chunk becomes one frame immediately. Good enough to observe raw bytes; not reliable for parsing.

**Delimiter (line-based protocols):**
```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    framer_name="delimiter",
    framer_kwargs={"delimiter": b"\r\n"},
)
```
The framer accumulates bytes until it sees `\r\n`, then emits everything before it as one frame.

**Length-prefix (binary protocols):**
```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 4, "byte_order": "big"},
)
```
The framer reads the first 4 bytes as a big-endian integer `N`, then buffers until it has exactly `N` more bytes, and emits the full `header + payload` as one frame.

**Custom framer (script file):**
```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    custom_framer_path="/path/to/my_framer.py",
)
```
The script just defines two functions — no imports from ProtoPoke needed. See the [Framer](#framer) chapter for the full API.

> **How to find the right framer:** capture a few raw frames first (`framer_name="raw"`), open them in a hex editor, and look for repeating patterns at fixed offsets. A 2- or 4-byte integer right at the start whose value matches the remaining byte count is a length prefix. Repeated `\x00` or `\r\n` terminations mean a delimiter framer.

---

### Step 2 — Build the parser

Once framing is correct (each `Frame` contains exactly one complete message), the second phase of reverse engineering begins: **understanding what the bytes mean**. You do this incrementally — start with just the header fields, then add more message types as you identify them, until the protocol is fully mapped.

A **parser definition** is a YAML (or JSON) file that describes the structure of each message type. ProtoPoke feeds every captured frame through the definition and converts raw bytes into named, typed fields — displayed in a Wireshark-style tree with a hex dump.

#### The incremental approach

Reverse engineering a protocol takes multiple passes. Don't try to define everything at once:

1. **Observe raw traffic** — use `framer_name="raw"` and capture several sessions. Look for repeating structures, length fields, opcode bytes.
2. **Fix framing** — get each frame to be exactly one atomic message (Step 1).
3. **Start with the header** — most binary protocols have a fixed-size header. Define those fields first (magic bytes, opcode, length field).
4. **Identify message types** — look for a type/opcode byte that routes to different payload layouts. Define a `match` rule for each type you find.
5. **Flesh out payloads** — add fields for each message type as you understand them. Use `type: bytes, length: -1` as a placeholder for parts you haven't decoded yet.
6. **Map enums and flags** — once you know what status codes and flag bits mean, add `enum` and `bitfield` definitions.
7. **Tackle composite structures** — add `array` and `tlv_sequence` when you spot repeating sub-structures or TLV-encoded blocks.

---

#### Definition file format

Create a `.yaml` (or `.json`) file:

```yaml
protocol:
  name: "MyProto"     # arbitrary label shown in the UI
  version: "1.0"      # optional
  endianness: big     # big or little — applies to all integer fields by default

  messages:
    - ...             # list of message type definitions, evaluated top-to-bottom
```

---

#### Message type definition

Each entry in `messages` describes one packet type:

```yaml
- name: "MessageTypeName"         # shown in UI / ParsedMessage.message_type
  description: "Optional note"    # shown in UI tooltip
  direction: client_to_server     # optional filter: client_to_server | server_to_client | both
  match:
    type: magic                   # magic | sequence | always
    ...                           # match-type-specific keys
  fields:
    - name: field_name
      type: field_type
      ...                         # type-specific options
```

---

#### Match types

There are three strategies for identifying a message type. The matcher evaluates definitions **top-to-bottom** and uses the first match — put specific rules before catch-alls.

**`magic` — match bytes at a fixed offset**

The most common strategy. Identify packets by a fixed opcode or magic sequence at a known position:

```yaml
match:
  type: magic
  offset: 0       # byte offset from the start of the frame
  value: "0x10"   # accepted formats: "0x10", 16, [0x10], "0x10 0x00", [0x10, 0x00]
```

Example — two-byte magic at offset 0:

```yaml
match:
  type: magic
  offset: 0
  value: [0xDE, 0xAD]
```

**`sequence` — match by stream position**

Use when the first N frames in a session have a known structure regardless of content (e.g., a banner or handshake):

```yaml
match:
  type: sequence
  direction: server_to_client   # required: which direction to count
  index: 0                      # 0-based: 0 = first frame in that direction
```

**`always` — catch-all**

Always matches. Use as the **last** entry to capture anything not handled by earlier definitions:

```yaml
match:
  type: always
```

---

#### Field types

All fields share these common keys:

| Key | Required | Description |
|---|---|---|
| `name` | yes | Unique identifier within the message; referenced in length expressions |
| `type` | yes | Field type (see below) |
| `display` | no | Rendering hint: `auto` (default), `hex`, `ascii`, `decimal`, `enum` |

**Integer**

```yaml
- name: opcode
  type: uint8     # uint8 | uint16 | uint32 | uint64 | int8 | int16 | int32 | int64
  display: hex    # optional; default is decimal
```

Sizes: `uint8`/`int8` = 1 B, `uint16`/`int16` = 2 B, `uint32`/`int32` = 4 B, `uint64`/`int64` = 8 B. All respect the top-level `endianness`.

**Float**

```yaml
- name: temperature
  type: float32   # float32 (4 B) | float64 (8 B)
```

**Bytes** — raw byte sequence

```yaml
- name: payload
  type: bytes
  length: "{payload_len}"   # required (see Length expressions below)
  display: hex
```

**String** — decoded text

```yaml
- name: username
  type: string
  length: "{username_len}"  # length in bytes (not characters)
  encoding: utf8            # utf8 (default) | ascii | utf16
  display: ascii

# Or null-terminated:
- name: hostname
  type: string
  null_terminated: true
  encoding: ascii
```

**Padding** — skip alignment or reserved bytes

```yaml
- name: reserved
  type: padding
  length: 3     # bytes to skip; value is not parsed or displayed
```

**Enum** — integer with named values

Any integer field can carry an `enum` map. Use `display: enum` to show the label instead of the raw number:

```yaml
- name: status
  type: uint8
  display: enum
  enum:
    0x00: "Success"
    0x01: "Not Found"
    0x02: "Permission Denied"
    0xFF: "Unknown Error"
```

**Bitfield** — integer decoded as individually named bits

```yaml
- name: flags
  type: bitfield
  bits:
    0: syn      # bit 0 (LSB)
    1: ack
    2: fin
    7: urgent   # bit 7
```

Each named bit becomes a child `ParsedField` with value `0` or `1`. The integer width is inferred from the highest bit index (rounds up to the nearest byte).

**Array** — counted sequence of identical sub-structures

```yaml
- name: records
  type: array
  array:
    count: "{record_count}"     # iterations; field reference or literal integer
    item:                       # sub-fields per iteration (same syntax as message fields)
      - { name: id,       type: uint32 }
      - { name: name_len, type: uint8  }
      - { name: name,     type: string, length: "{name_len}", encoding: utf8 }
      - name: flags
        type: bitfield
        bits:
          0: active
          1: admin
```

**TLV sequence** — stream of Type-Length-Value triples

```yaml
- name: attributes
  type: tlv_sequence
  length: "{total_length - 5}"    # bytes the entire TLV block spans
  tlv:
    type_size: 2                  # bytes for the type field (1, 2, or 4)
    length_size: 2                # bytes for the length field (1, 2, or 4)
    endianness: big               # byte order for type/length fields
    tags:
      0x0001:
        name: "UserID"
        value_type: uint32
      0x0002:
        name: "Username"
        value_type: string
        encoding: utf8
      0x0003:
        name: "Blob"
        value_type: bytes
        display: hex
```

---

#### Length expressions

The `length` and `count` keys accept several formats:

| Format | Example | Meaning |
|---|---|---|
| Fixed integer | `4` | Always 4 bytes |
| Field reference | `"{payload_len}"` | Value of a previously parsed field |
| Arithmetic expression | `"{total_length - 5}"` | `total_length` minus 5 |
| Rest of frame | `-1` | Consume all remaining bytes |
| Null terminated | `null_terminated: true` | Scan until `\x00` byte |

Expressions support `+`, `-`, `*`, `//` and builtins `min()`, `max()`, `abs()`, `int()`. Field names in `{}` are substituted by their parsed integer value. Evaluation is sandboxed (no imports, no attribute access).

---

#### Configure the parser in the app

**Via config (recommended):**

```python
from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig

config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 2, "byte_order": "big"},
    protocol_definition_path="myproto.yaml",   # .yaml, .yml, or .json
)
api = ProxyAPI(config)
await api.start()
```

The definition is loaded automatically when `start()` is called. Every frame captured from that point on is parsed against it.

**Via TUI:**

Open the **Config** tab, set `Protocol Definition File` to the path of your `.yaml` file, and click **Apply**. The parser takes effect immediately for new sessions.

**Hot-swap at runtime (API):**

```python
# Load from file
api.set_protocol_file("myproto.yaml")

# Load from a dict (useful in tests / scripts)
api.set_protocol_dict({
    "name": "MyProto",
    "endianness": "big",
    "messages": [...],
})
```

---

#### Working with parsed messages

```python
# Tamper — get both the raw tamper unit and the parsed message
unit, msg = await api.get_next_intercepted_parsed()

print(msg.message_type)           # e.g. "LoginRequest"
print(msg.protocol_name)          # e.g. "MyProto"

# Access a field by name
f = msg.field_by_name("username")
print(f.value)           # Python value: str, int, bytes, list[ParsedField]
print(f.display_value)   # pre-rendered string, e.g. "0x4142" or "AB"
print(f.offset)          # byte offset in the frame
print(f.size)            # bytes consumed

# All fields as a flat dict
print(msg.as_dict())     # {"opcode": 1, "username": "admin", ...}

# Forward after editing one field (length fields are auto-recomputed)
api.modify_field_and_forward(unit.id, {"username": "hacker"})
```

---

#### Building a definition iteratively: worked example

Suppose you have frames and can see (in hex) that each starts with a 1-byte opcode. Start minimal and expand:

**Pass 1 — skeleton: just split the opcode from the rest**

```yaml
protocol:
  name: "Unknown"
  endianness: big

  messages:
    - name: "Packet"
      match:
        type: always
      fields:
        - { name: opcode, type: uint8,  display: hex }
        - { name: rest,   type: bytes,  length: -1,  display: hex }
```

Now every captured frame shows its opcode. Once you identify opcode `0x01` as a login request, add it:

**Pass 2 — add a named message type**

```yaml
    - name: "LoginRequest"
      direction: client_to_server
      match:
        type: magic
        offset: 0
        value: "0x01"
      fields:
        - { name: opcode, type: uint8, display: hex }
        - { name: rest,   type: bytes, length: -1,  display: hex }   # placeholder

    - name: "Packet"   # fallback
      match:
        type: always
      fields:
        - { name: opcode, type: uint8, display: hex }
        - { name: rest,   type: bytes, length: -1,  display: hex }
```

**Pass 3 — flesh out the payload**

Look at the `rest` bytes in `LoginRequest` frames. If bytes 1–2 look like a big-endian length followed by that many bytes of ASCII text, add:

```yaml
      fields:
        - { name: opcode,        type: uint8  }
        - { name: username_len,  type: uint16 }
        - { name: username,      type: string, length: "{username_len}", encoding: utf8 }
        - { name: password_len,  type: uint16 }
        - { name: password,      type: bytes,  length: "{password_len}", display: hex }
        # no more "rest" — the whole frame is accounted for
```

Repeat this process for every message type until no `rest` placeholders remain.

A complete working example covering all field types (enum, bitfield, array, TLV) is at `examples/protocols/chat.proto.yaml`.
A DNS over TCP example is at `examples/protocols/dns.proto.yaml`.

---

## Framer

### What a framer does

TCP is a **byte stream** — the OS delivers bytes in arbitrary chunks that bear no relation to the application's message boundaries. A single `read()` may return half a message, exactly one message, or three messages fused together.

The framer is the **first processing phase** for every byte that arrives on a proxied connection. Its job is to cut the raw stream into discrete, atomic units called **frames** — one frame = one complete application-level message. Everything downstream (tamper, protocol dissection, forge/replay, fuzzing) operates on frames, so getting the framing right is the prerequisite for everything else.

ProtoPoke runs one framer instance per direction per session:

```
client ──bytes──▶ [client→server framer] ──frames──▶ tamper / dissect / log
server ──bytes──▶ [server→client framer] ──frames──▶ tamper / dissect / log
```

---

### Built-in framers

Configure a built-in framer with `framer_name` (and optional `framer_kwargs`) in `ProxyConfig`:

#### `raw` (default)

Every `read()` chunk becomes one frame immediately. No buffering, no boundary detection. Good for an initial capture to observe raw bytes; unreliable for parsing because frame boundaries depend on OS scheduling.

```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    # framer_name defaults to "raw"
)
```

#### `delimiter`

Accumulates bytes until a configurable byte sequence appears, then emits everything before it as one frame. The delimiter itself is consumed and not included in the frame.

```python
# Split on newline (HTTP headers, SMTP, FTP, Redis inline commands)
config = ProxyConfig(..., framer_name="delimiter", framer_kwargs={"delimiter": b"\n"})

# Split on CRLF
config = ProxyConfig(..., framer_name="delimiter", framer_kwargs={"delimiter": b"\r\n"})

# Split on null byte (C-string protocols)
config = ProxyConfig(..., framer_name="delimiter", framer_kwargs={"delimiter": b"\x00"})

# Split on a multi-byte magic sequence
config = ProxyConfig(..., framer_name="delimiter", framer_kwargs={"delimiter": b"\xff\xfe"})
```

#### `length_prefix`

Reads a fixed-size integer at the start of each message that declares how many bytes follow, then buffers until exactly that many bytes have arrived and emits the full `prefix + payload` as one frame.

```python
# 4-byte big-endian length field (most common binary protocol layout)
config = ProxyConfig(
    ...,
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 4, "byte_order": "big"},
)

# 2-byte little-endian length field
config = ProxyConfig(
    ...,
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 2, "byte_order": "little"},
)

# Length field is at byte offset 3 (skip a 3-byte header first)
config = ProxyConfig(
    ...,
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 2, "byte_order": "big", "prefix_offset": 3},
)

# Length field counts only the payload; add 6 to include the header in the frame
config = ProxyConfig(
    ...,
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 2, "byte_order": "big", "length_add": 6},
)
```

`prefix_length` accepts 1, 2, 4, or 8 bytes. `byte_order` accepts `"big"` or `"little"`.

#### `line`

Convenience wrapper around `delimiter` that splits on `\r\n` and also accepts bare `\n`. Useful for HTTP/1.x header parsing or any human-readable line-oriented protocol.

```python
config = ProxyConfig(..., framer_name="line")
```

---

### Custom framer

When none of the built-in framers fit, write a Python script with two functions. No class, no inheritance, no imports from ProtoPoke.

#### How to load it

```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    custom_framer_path="/path/to/my_framer.py",
)
```

`custom_framer_path` takes precedence over `framer_name`. ProtoPoke discovers the functions automatically — no class name or registration required.

In the TUI: **Config tab → Edit Framer → Custom → Script path**.

#### The two functions

```python
def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    ...

def on_flush(state: dict, direction: str) -> list[bytes]:
    ...
```

#### `on_data(data, state, direction)`

Called every time bytes arrive from the network. May be called many times per message (TCP segments arrive piecemeal) or once with several messages fused together. Must handle both cases by buffering internally.

| Argument | Type | Description |
|---|---|---|
| `data` | `bytes` | Raw bytes from the latest `read()` call. Append them to your buffer. |
| `state` | `dict` | Mutable dict shared between **both** directions for this session. Persists for the lifetime of the connection. Use it for per-direction buffers and any cross-direction state your protocol needs (see below). |
| `direction` | `str` | `"c2s"` (client → server) or `"s2c"` (server → client). |

**Return value:** `list[bytes]` — zero or more complete message payloads. Return `[]` if you need more data before a boundary can be found.

#### `on_flush(state, direction)`

Called once when the underlying TCP connection closes, giving the framer a chance to emit any bytes that were buffered but never completed a full message. Nothing should be silently discarded — return whatever is left.

| Argument | Type | Description |
|---|---|---|
| `state` | `dict` | Same shared dict as `on_data`. |
| `direction` | `str` | `"c2s"` or `"s2c"`. |

**Return value:** `list[bytes]` — zero or one partial frame. Typically `[bytes(buf)]` if the buffer is non-empty, `[]` otherwise.

#### The `state` dict — buffers and cross-direction correlation

`state` is created **once per connection** and passed to every `on_data` and `on_flush` call for **both** directions. This design has two consequences:

**1. Per-direction buffering** — use `direction` as a key so each side has its own accumulation buffer:

```python
def on_data(data, state, direction):
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    # ... detect boundaries in buf and return complete frames ...
```

**2. Cross-direction correlation** — protocols where the server response format depends on what the client sent can share state freely:

```python
def on_data(data, state, direction):
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)

    if direction == "c2s":
        # Parse the client's command and record it for the server side
        if len(buf) >= 1:
            state["last_cmd"] = buf[0]
            # ... parse and return client frames ...

    else:  # "s2c"
        cmd = state.get("last_cmd")
        # ... parse server response differently depending on cmd ...
```

`on_flush` receives the same `state`, so you can also check cross-direction state there.

#### Minimal example — fixed 4-byte length prefix

```python
import struct

def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    frames = []
    while len(buf) >= 4:
        (length,) = struct.unpack_from(">I", buf, 0)   # big-endian uint32
        total = 4 + length
        if len(buf) < total:
            break                                        # incomplete — wait
        frames.append(bytes(buf[:total]))
        del buf[:total]
    return frames

def on_flush(state: dict, direction: str) -> list[bytes]:
    buf = state.pop(direction, bytearray())
    return [bytes(buf)] if buf else []
```

#### Example — delimiter (manual)

```python
DELIMITER = b"\r\n"

def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    frames = []
    while True:
        idx = buf.find(DELIMITER)
        if idx == -1:
            break
        frames.append(bytes(buf[:idx]))   # exclude delimiter
        del buf[:idx + len(DELIMITER)]
    return frames

def on_flush(state: dict, direction: str) -> list[bytes]:
    buf = state.pop(direction, bytearray())
    return [bytes(buf)] if buf else []
```

#### Example — DNS over TCP (RFC 1035 §4.2.2)

DNS over TCP prefixes every message with a 2-byte big-endian length (payload only, prefix not counted). This example also shows desync recovery: if the declared length looks implausible, the bad bytes are emitted as a raw frame and framing restarts.

```python
import struct

_DNS_MIN = 12   # smallest valid DNS message (fixed header, no records)

def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    frames = []
    while len(buf) >= 2:
        (msg_len,) = struct.unpack_from(">H", buf, 0)
        if msg_len < _DNS_MIN or msg_len > 0xFFFF:
            # Implausible — desynced. Flush buffer and restart.
            frames.append(bytes(buf))
            buf.clear()
            break
        total = 2 + msg_len
        if len(buf) < total:
            break                          # incomplete — wait
        frames.append(bytes(buf[:total]))  # prefix + DNS message
        del buf[:total]
    return frames

def on_flush(state: dict, direction: str) -> list[bytes]:
    buf = state.pop(direction, bytearray())
    return [bytes(buf)] if buf else []
```

A standalone runnable version of this framer lives in [`examples/dns_framer.py`](examples/dns_framer.py).

#### Desync recovery

If your protocol has no reliable sync markers (DNS over TCP being a classic example), the safest desync strategy is to flush the entire buffer and restart:

```python
# Desync: emit everything buffered as a single raw frame, then restart clean
frames.append(bytes(buf))
buf.clear()
break
```

If your protocol *does* have sync markers (e.g. a magic header `0xAB 0xCD` that starts every frame), scan for the next one to skip as few bytes as possible:

```python
MAGIC = b"\xab\xcd"

def _recover(buf: bytearray) -> int:
    """Return how many bytes to skip. 0 = need more data."""
    idx = buf.find(MAGIC, 1)          # start at 1 to skip current bad position
    return idx if idx != -1 else len(buf)
```

#### Tips

- **Always use `state.setdefault(direction, bytearray())`** for your buffer — never a module-level variable, which would be shared across all sessions.
- **Never modify `data` directly.** Append it to your buffer, then slice from the buffer.
- **Return complete frames only.** If you are not sure a frame is complete, return `[]` and wait for the next `on_data` call.
- **`on_flush` should drain the buffer**, not leave bytes behind. Whatever is in the buffer when the connection closes is the last chance to capture it.
- **Test with a smoke-test script.** Call `on_data` / `on_flush` directly with synthetic payloads before wiring up a live proxy. See the DNS and FrameSize examples in `examples/`.

---

## start() vs serve_forever()

`ProxyAPI` has two ways to run:

| Method | Behaviour | When to use |
|---|---|---|
| `await api.start()` | Binds the port and returns immediately | When you need to do other work concurrently (intercept loop, test assertions, second server, …). You must call `await api.stop()` yourself. |
| `await api.serve_forever()` | Calls `start()` then blocks until the process is killed | Standalone scripts where the proxy is the only thing running. No need to call `stop()`. |

```python
# Standalone script — serve_forever() is simplest
async def main():
    api = ProxyAPI(config)
    await api.serve_forever()          # blocks here; Ctrl-C to exit

# Proxy + tamper loop — use start() so both can run concurrently
async def main():
    api = ProxyAPI(config)
    await api.start()
    try:
        while True:
            unit = await api.get_next_intercepted()
            api.forward(unit.id)
    finally:
        await api.stop()               # always clean up
```

---

## Quick Start

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig

async def main():
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
    )
    api = ProxyAPI(config)
    await api.serve_forever()   # standalone script: blocks until Ctrl-C

asyncio.run(main())
```

Connect anything to `127.0.0.1:8080` and traffic is transparently forwarded to `10.0.0.1:9090`.

---

## Examples

### 1 — Passive capture with frame printing

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig
from protopoke.events.bus import FrameCapturedEvent

async def main():
    config = ProxyConfig(listen_port=8080, upstream_host="10.0.0.1", upstream_port=9090)
    api = ProxyAPI(config)

    async def on_frame(event: FrameCapturedEvent):
        arrow = "→" if event.frame.direction.value == "client_to_server" else "←"
        print(f"[{event.session.id[:8]}] {arrow} {event.frame.raw_bytes!r}")

    api.on_frame_captured(on_frame)
    await api.serve_forever()

asyncio.run(main())
```

> See `examples/simple_proxy.py` for a more complete version.

---

### 2 — Tamper, inspect, and modify frames

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig

async def main():
    config = ProxyConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
    )
    api = ProxyAPI(config)
    await api.start()
    try:
        while True:
            unit = await api.get_next_intercepted()
            frame = unit.frame

            print(f"Tampered [{frame.direction.value}]: {frame.raw_bytes!r}")

            api.forward(unit.id)                      # forward as-is
            # api.drop(unit.id)                       # discard
            # api.modify_and_forward(unit.id, b"new data")
    finally:
        await api.stop()

asyncio.run(main())
```

> See `examples/tamper_demo.py` for an interactive CLI version with hex editing.

---

### 3 — Toggle tamper mode at runtime

```python
# Disable — all pending frames are immediately forwarded
api.tamper_enabled = False

# Re-enable
api.tamper_enabled = True

# Forward everything currently queued (without disabling)
api.forward_all()
```

---

### 4 — Replay a captured session

```python
# After a session has closed:
result = await api.replay_session(session_id)

print(f"Sent {result.total_bytes_sent()} bytes")
for frame in result.server_frames_received():
    print(frame.raw_bytes)
```

Replay to a different server, or with modified frames:

```python
result = await api.replay_session(
    session_id,
    server_host="staging.internal",
    server_port=9090,
    modified_frames={frame_id: b"modified payload"},
)
```

> See `examples/replay_demo.py` for a full interactive demo.

---

### 5 — Protocol-aware framing

By default every `read()` chunk becomes one frame (raw framer). For line-based protocols:

```python
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    framer_name="delimiter",
    framer_kwargs={"delimiter": b"\r\n"},
)
```

For length-prefix binary protocols:

```python
config = ProxyConfig(
    framer_name="length_prefix",
    framer_kwargs={"prefix_length": 4, "byte_order": "big"},
)
```

---

### 6 — Inspect captured sessions

```python
from protopoke.models import Direction

sessions = api.list_sessions()
for session in sessions:
    print(session)

# Get frames for one session
frames = api.get_frames(session.id, direction=Direction.CLIENT_TO_SERVER)
for frame in frames:
    print(f"seq={frame.sequence_number}  {frame.raw_bytes.hex()}")
```

---

### 7 — Event subscriptions

```python
from protopoke.events.bus import SessionOpenedEvent, SessionClosedEvent

async def on_open(event: SessionOpenedEvent):
    print(f"Session opened: {event.session.id}")

async def on_close(event: SessionClosedEvent):
    print(f"Session closed: {event.session.id}")

api.on_session_opened(on_open)
api.on_session_closed(on_close)
```

---

### 8 — TLS MITM (Burp-style)

On first run the proxy auto-generates a root CA at `~/.protopoke/ca.crt`. Install that file as a trusted root in your client (browser, OS, curl, etc.) once. Every subsequent session gets a fresh CA-signed leaf certificate transparently.

```python
config = ProxyConfig(
    listen_port=8443,
    upstream_host="api.example.com",
    upstream_port=443,
    tls_listen=True,         # present CA-signed cert to clients
    tls_upstream=True,       # connect to the real server over TLS
    # tls_upstream_verify=False,  # uncomment to accept self-signed server certs
)
api = ProxyAPI(config)
await api.start()

# Export the CA cert so the client can trust it
with open("protopoke-ca.crt", "wb") as f:
    f.write(api.ca.cert_pem)
print("Install protopoke-ca.crt as a trusted root, then connect to localhost:8443")
```

Supply your own certificate instead of using the auto-CA:

```python
config = ProxyConfig(
    listen_port=8443,
    upstream_host="api.example.com",
    upstream_port=443,
    tls_listen=True,
    tls_cert_path="/path/to/wildcard.crt",
    tls_key_path="/path/to/wildcard.key",
    tls_upstream=True,
    tls_upstream_verify=False,
)
```

---

### 9 — Protocol definitions

Define your protocol in a YAML file. Point the proxy at it and every captured frame is automatically decoded into named fields.

#### YAML definition format

Three ways to identify packet types:

```yaml
protocol:
  name: "MyProtocol"
  endianness: big          # or little

  messages:

    # Magic bytes at a fixed offset
    - name: "LoginRequest"
      direction: client_to_server
      match:
        type: magic
        offset: 0
        value: "0x01"
      fields:
        - { name: opcode,        type: uint8  }
        - { name: username_len,  type: uint16 }
        - { name: username,      type: string, length: "{username_len}", encoding: utf8 }
        - { name: password_len,  type: uint16 }
        - { name: password,      type: bytes,  length: "{password_len}", display: hex }

    # Stream sequence position
    - name: "ServerBanner"
      match:
        type: sequence
        direction: server_to_client
        index: 0
      fields:
        - { name: banner, type: string, length: -1, encoding: ascii }

    # TLV-structured payload
    - name: "DataPacket"
      match:
        type: magic
        offset: 0
        value: "0x10"
      fields:
        - { name: opcode,        type: uint8  }
        - { name: total_length,  type: uint32 }
        - name: attributes
          type: tlv_sequence
          length: "{total_length - 5}"
          tlv:
            type_size: 2
            length_size: 2
            tags:
              0x0001: { name: "ChannelID",   value_type: uint32 }
              0x0002: { name: "ChannelName", value_type: string }
              0x0003: { name: "Payload",     value_type: bytes,  display: hex }

    # Array of repeated sub-structures
    - name: "UserList"
      match:
        type: magic
        offset: 0
        value: "0x20"
      fields:
        - { name: opcode,      type: uint8  }
        - { name: user_count,  type: uint16 }
        - name: users
          type: array
          array:
            count: "{user_count}"
            item:
              - { name: user_id,  type: uint32 }
              - { name: name_len, type: uint8  }
              - { name: name,     type: string, length: "{name_len}" }
              - name: flags
                type: bitfield
                bits:
                  0: online
                  1: away
                  2: admin

    # Catch-all
    - name: "Unknown"
      match:
        type: always
      fields:
        - { name: raw, type: bytes, length: -1, display: hex }
```

A complete working example is at `examples/protocols/chat.proto.yaml`.

#### Field type reference

| Type | Size | Notes |
|---|---|---|
| `uint8` / `uint16` / `uint32` / `uint64` | 1 / 2 / 4 / 8 B | Unsigned integer |
| `int8` / `int16` / `int32` / `int64` | 1 / 2 / 4 / 8 B | Signed integer |
| `float32` / `float64` | 4 / 8 B | IEEE 754 |
| `bytes` | variable | Raw bytes; `length` required |
| `string` | variable | Decoded text; `length` or `null_terminated: true` |
| `bitfield` | variable | Integer with named per-bit children |
| `array` | variable | Repeated sub-structure; `array.count` required |
| `tlv_sequence` | variable | Stream of T-L-V triples; `tlv` config required |
| `padding` | variable | Skip N bytes (alignment / reserved) |

Field `length` sources:
- Fixed integer: `length: 4`
- Another field: `length: "{username_len}"`
- Expression: `length: "{total_length - 5}"`
- Rest of frame: `length: -1`
- Null-terminated string: `null_terminated: true`

#### Loading a definition

```python
# Via config — auto-loaded on start()
config = ProxyConfig(
    listen_port=8080,
    upstream_host="10.0.0.1",
    upstream_port=9090,
    protocol_definition_path="myproto.yaml",  # .yaml, .yml, or .json
)

# Or at runtime
api.set_protocol_file("myproto.yaml")

# Or from a dict (useful in tests / scripts)
api.set_protocol_dict({"name": "MyProto", "messages": [...]})
```

#### Decoding frames

```python
msg = api.decode_frame(frame)
print(msg.message_type)   # e.g. "LoginRequest"
for field in msg.fields:
    print(f"  {field.name}: {field.display_value}  (offset={field.offset}, size={field.size})")

msg.field_by_name("username").value    # Python value (str, int, bytes, …)
msg.as_dict()                          # {field_name: value, …}
```

---

### 10 — Protocol-aware tamper

```python
unit, msg = await api.get_next_intercepted_parsed()

print(msg.message_type)               # "LoginRequest"
print(msg.field_by_name("username").value)  # "admin"

# Forward after editing a single field — length fields are auto-recomputed
api.modify_field_and_forward(unit.id, {"username": "hacker"})

# Or fall back to raw bytes
api.modify_and_forward(unit.id, b"\x01\x00\x06hacker...")
```

---

### 11 — Protocol-aware replay

```python
result = await api.replay_session_with_field_edits(
    session_id=session_id,
    field_edits={
        "LoginRequest": {
            "username": "admin2",
            "password": b"newpassword",
        },
    },
)
```

---

### 12 — Wireshark-style display

```python
from protopoke.protocol.display import (
    render_hexdump,
    render_field_tree,
    render_frame_header,
    highlights_from_message,
)

msg = api.decode_frame(frame)

# One-line summary
print(render_frame_header(frame, msg))
# Frame #3  C→S  10:23:45.123  48 bytes  [ChatProtocol] LoginRequest

# Field detail panel
print(render_field_tree(msg))
# ┌─ ChatProtocol / LoginRequest ─────────────────────────────────────┐
# │  opcode       [0x0000,  1B]   0x01                                │
# │  username_len [0x0001,  2B]   5                                   │
# │  username     [0x0003,  5B]   admin                               │
# └────────────────────────────────────────────────────────────────────┘

# Hex dump with per-field colour highlights
highlights = highlights_from_message(msg)
print(render_hexdump(frame.raw_bytes, highlights=highlights))
```

---

### 13 — Fuzzing a captured session

Fuzzing works in three steps: **capture** a normal session through the proxy, **run** a campaign with one or more mutators, **review** the results.

```python
import asyncio
from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig
from protopoke.fuzzing.mutators import BitFlipMutator, KnownBadMutator

async def main():
    config = ProxyConfig(
        listen_port=8080,
        upstream_host="10.0.0.1",
        upstream_port=9090,
        framer_name="length_prefix",
        framer_kwargs={"prefix_length": 4, "byte_order": "big"},
        protocol_definition_path="myproto.yaml",   # optional but unlocks field mutators
    )
    api = ProxyAPI(config)
    await api.start()

    # --- Step 1: capture a real session ---
    # Connect your client through the proxy; when it disconnects the session is complete.
    input("Connect your client, then press Enter…")
    session_id = api.list_sessions()[-1].id
    print(f"Template session: {session_id}")

    # --- Step 2: fuzz ---
    campaign = await api.fuzz_session(
        session_id=session_id,
        mutators=[BitFlipMutator(), KnownBadMutator()],
        iterations=100,
        stop_on_crash=True,                      # stop on TCP RST
        on_result=lambda r: print(
            f"  [{r.iteration:3d}] {r.mutator_name:<14} "
            f"resp={r.response_size:5d}B  Δ={r.response_size_delta:+d}  "
            f"{'★ INTERESTING' if r.interesting else ''}"
        ),
    )

    # --- Step 3: review ---
    print(f"\nDone — {campaign.completed_iterations} iterations")
    print(f"Interesting: {len(campaign.interesting_results)}")
    print(f"Crashes:     {len(campaign.crash_results)}")

    await api.stop()

asyncio.run(main())
```

#### Targeting specific frames

Use `frame_selector` to restrict mutations to particular frames — same syntax as `replay_session()`:

```python
campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[BitFlipMutator()],
    iterations=50,
    frame_selector="2",      # only fuzz frame with sequence_number=2
    # frame_selector="0,2-4" # frames 0, 2, 3, 4
)
```

#### Protocol-aware mutators

When a protocol definition is loaded (`api._encoder is not None`), field-aware mutators can target individual fields while keeping the rest of the packet structurally valid. The encoder auto-recomputes length fields, so mutations reach deeper into the application parser.

```python
from protopoke.fuzzing.mutators import (
    FieldBoundaryMutator,   # set integer fields to 0, -1, MAX, MAX+1, …
    FieldOverflowMutator,   # replace string/bytes fields with A×256, A×1024, …
    NullByteMutator,        # inject \x00 mid-string
    LengthMangleMutator,    # corrupt length-named fields (data_len, size, …)
)

encoder = api._encoder     # set after api.set_protocol_file() / api.start()

campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[
        FieldBoundaryMutator(encoder),
        FieldOverflowMutator(encoder, lengths=[256, 1024, 4096]),
        NullByteMutator(encoder),
        LengthMangleMutator(encoder),
    ],
    iterations=200,
)
```

`FieldOverflowMutator` will, for example, replace the `username` field with 1 024 `A` bytes and let the encoder update `username_len` automatically — producing a structurally valid but content-overflowing packet.

#### Chaining mutators

Apply multiple mutations in sequence with `ChainMutator`. Each mutator in the chain receives the output of the previous one:

```python
from protopoke.fuzzing.mutators import ChainMutator, FieldOverflowMutator, BitFlipMutator

chain = ChainMutator([
    FieldOverflowMutator(encoder, lengths=[256]),  # extend a field
    BitFlipMutator(count=3),                       # then flip 3 bits anywhere
])

campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[chain],
    iterations=50,
)
```

#### Using radamsa

[radamsa](https://gitlab.com/akihe/radamsa) is a battle-tested mutation fuzzer. If it is on your `PATH`, `RadamsaMutator` pipes each frame through it. If radamsa is not installed, it falls back to `BitFlipMutator` automatically — no error, no crash.

```python
from protopoke.fuzzing.mutators import RadamsaMutator

campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[RadamsaMutator()],     # uses "radamsa" on PATH
    iterations=100,
)

# Or point at a non-standard binary:
campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[RadamsaMutator(radamsa_path="/opt/radamsa/bin/radamsa")],
    iterations=100,
)
```

---

### 14 — Writing a custom mutator

Subclass `FrameMutator` and implement one async method. The method receives the raw `Frame` and, if a protocol definition is loaded, the decoded `ParsedMessage`. Return mutated bytes, or `None` to skip this iteration.

#### Minimal example — raw mutation (no protocol knowledge)

```python
from protopoke.fuzzing.mutators.base import FrameMutator

class XorMutator(FrameMutator):
    """XOR every byte with a fixed key."""

    def __init__(self, key: bytes = b"\xde\xad"):
        self._key = key

    @property
    def name(self) -> str:
        return f"XOR({self._key.hex()})"

    async def mutate(self, frame, parsed):
        return bytes(
            b ^ self._key[i % len(self._key)]
            for i, b in enumerate(frame.raw_bytes)
        )
```

Use it exactly like any built-in mutator:

```python
campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[XorMutator(b"\xff"), BitFlipMutator()],
    iterations=50,
)
```

#### Protocol-aware example — target a specific field

When `parsed` is not `None` you have full access to every decoded field (name, value, offset, size). Use the encoder to rebuild the packet with your modification so length fields are recomputed correctly.

```python
import random
from protopoke.fuzzing.mutators.base import FrameMutator

class FormatStringMutator(FrameMutator):
    """Inject format-string payloads into every string field."""

    _PAYLOADS = ["%s%s%n", "%x%x%x%x", "%p%p%p%p", "%.10000d"]

    def __init__(self, encoder):
        self._encoder = encoder

    @property
    def name(self) -> str:
        return "FormatString"

    async def mutate(self, frame, parsed):
        if parsed is None:
            return None   # no protocol definition loaded, skip

        string_fields = [f for f in parsed.fields if isinstance(f.value, str)]
        if not string_fields:
            return None   # no string fields in this message type, skip

        target  = random.choice(string_fields)
        payload = random.choice(self._PAYLOADS)

        try:
            return self._encoder.encode_with_edits(parsed, {target.name: payload})
        except Exception:
            return None   # encoder rejected the value, skip
```

#### External-tool wrapper

```python
import asyncio
from protopoke.fuzzing.mutators.base import FrameMutator
from protopoke.fuzzing.mutators.raw import BitFlipMutator

class HonggfuzzMutator(FrameMutator):
    """Pipe the frame through honggfuzz-mutator (if installed)."""

    async def mutate(self, frame, parsed):
        try:
            proc = await asyncio.create_subprocess_exec(
                "honggfuzz-mutator",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(frame.raw_bytes), timeout=5.0)
            return out if out else None
        except (FileNotFoundError, asyncio.TimeoutError):
            return await BitFlipMutator().mutate(frame, parsed)  # fallback
```

#### Combining built-in and custom mutators

Custom mutators compose with everything else:

```python
campaign = await api.fuzz_session(
    session_id=session_id,
    mutators=[
        BitFlipMutator(),
        KnownBadMutator(),
        FormatStringMutator(api._encoder),
        ChainMutator([FormatStringMutator(api._encoder), BitFlipMutator(count=2)]),
    ],
    iterations=200,
    stop_on_crash=True,
)
```

---

## Repository Layout

```
protopoke/
├── pyproject.toml
├── protopoke/
│   ├── models.py           # Core data: Frame, ParsedField, ParsedMessage, SessionInfo, TamperedUnit
│   ├── config.py           # ProxyConfig dataclass (networking, TLS, framing, protocol)
│   ├── api.py              # ProxyAPI — the unified control facade
│   ├── core/
│   │   ├── proxy.py        # ProxyEngine: listen, connect upstream, wire relay + TLS
│   │   ├── relay.py        # DirectionalRelay + BidirectionalRelay
│   │   └── session.py      # Session + SessionRegistry
│   ├── tls/
│   │   ├── ca.py           # CertificateAuthority: generate, persist, issue leaf certs
│   │   └── handler.py      # TLSHandler: build SSLContext for listen + upstream sides
│   ├── framing/
│   │   ├── base.py         # Framer abstract base class
│   │   ├── raw.py          # Passthrough: each read() chunk = one frame
│   │   ├── delimiter.py    # Split on a fixed byte sequence
│   │   └── length_prefix.py # Fixed-size integer length header (1/2/4/8 bytes)
│   ├── protocol/
│   │   ├── base.py         # ProtocolDecoder / ProtocolEncoder ABCs + PassthroughDecoder
│   │   ├── definition/
│   │   │   ├── schema.py   # Dataclasses: ProtocolDefinition, MessageDefinition, FieldDefinition, …
│   │   │   └── loader.py   # Load + validate from YAML / JSON / dict
│   │   ├── parser/
│   │   │   ├── engine.py   # DefinitionBasedDecoder (session-aware) + DefinitionBasedEncoder
│   │   │   ├── fields.py   # Per-type parsers → ParsedField; encode_field() for re-assembly
│   │   │   ├── matcher.py  # MessageMatcher: magic / sequence / always match rules
│   │   │   └── expression.py # Safe AST-gated evaluator for "{length_field - 5}" strings
│   │   └── display/
│   │       ├── hexdump.py  # Wireshark-style hex+ASCII dump with ANSI field highlights
│   │       └── tree.py     # Box-drawing field detail panel with nested TLV/array children
│   ├── tamper/
│   │   └── controller.py   # PassthroughController + QueuedTamperController
│   ├── rules/
│   │   ├── rule.py         # InterceptRule, ReplaceRule dataclasses + RuleAction enum
│   │   ├── engine.py       # RulesEngine: ordered replace-rule pipeline
│   │   └── filter.py       # InterceptFilter: ordered intercept-rule evaluation
│   ├── fuzzing/
│   │   ├── models.py       # FuzzResult (anomaly heuristic) + FuzzCampaign
│   │   ├── engine.py       # FuzzerEngine: baseline capture, round-robin mutation loop, crash detection
│   │   └── mutators/
│   │       ├── base.py     # FrameMutator ABC — one async method, optional name property
│   │       ├── raw.py      # BitFlipMutator, ByteInsertMutator, ByteDeleteMutator,
│   │       │               # KnownBadMutator, RadamsaMutator (radamsa fallback), ChainMutator
│   │       └── field.py    # FieldBoundaryMutator, FieldOverflowMutator,
│   │                       # NullByteMutator, LengthMangleMutator (protocol-aware, encoder-backed)
│   ├── forge/
│   │   ├── engine.py       # ForgeEngine + ForgeResult (direction filter, frame selector)
│   │   └── models.py       # ForgeRequest + ForgeRecord (for the UI forge tab)
│   ├── project/
│   │   └── manager.py      # ProjectManager: new/open/save project files (JSON)
│   ├── storage/
│   │   └── base.py         # StorageBackend ABC, NullStorage, MemoryStorage
│   ├── events/
│   │   └── bus.py          # EventBus (pub/sub, async handlers)
│   ├── mcp/
│   │   ├── server.py       # FastMCP server: 50+ tools covering all ProxyAPI operations
│   │   └── runner.py       # CLI entry point for protopoke-mcp / protopoke --mcp
│   └── ui/
│       ├── app.py          # ProtoPoke(App) — main Textual application, event bridge
│       ├── tabs/
│       │   ├── config.py   # ConfigTab — proxy configuration form
│       │   ├── traffic.py  # TrafficTab — sessions, frames, hex/parsed detail
│       │   ├── tamper.py   # TamperTab — queue, hex editor, tamper/replace rules
│       │   ├── forge.py    # ForgeTab — hand-craft and replay frames
│       │   └── fuzzer.py   # FuzzerTab — campaign config, mutator checkboxes, live results table
│       ├── modals/
│       │   ├── project.py  # NewProjectModal, OpenProjectModal, SaveAsModal
│       │   ├── new_request.py # NewRequestModal — create a forge request
│       │   └── add_rule.py # AddInterceptRuleModal, AddReplaceRuleModal
│       └── widgets/
│           ├── rule_table.py # RuleTable — DataTable + Add/Remove/Move toolbar
│           └── parsed_view.py # ParsedView — hex ↔ field-tree toggle pane
├── tests/                  # Unit + integration tests
└── examples/
    ├── simple_proxy.py                 # Passthrough with frame printing
    ├── tamper_demo.py                  # Interactive CLI tamper / hex edit
    ├── replay_demo.py                  # Capture and replay sessions
    ├── protocol_tamper_demo.py         # Protocol-aware tamper with field editing
    ├── protocol_replay_demo.py         # Protocol-aware replay with field edits
    └── protocols/
        └── chat.proto.yaml             # Full example: magic, sequence, TLV, array, bitfield
```

---

## Key Design Decisions and Tradeoffs

### `asyncio` as the concurrency model

TCP proxying is entirely I/O-bound. `asyncio` handles many concurrent sessions in one thread with no locking — the session registry and tamper queue are shared safely because everything runs on the same event loop.

The tamper "pause" is implemented with `asyncio.Future`. When a frame is tampered, the relay task awaits the future. Only that one relay direction suspends; the event loop stays alive and continues handling all other sessions, new connections, and the API. With threads you would need a queue and a lock.

**Tradeoff:** CPU-bound work (e.g. heavy protocol decoding) would block the event loop. For this use case (personal research tool, not a high-throughput pipeline) that's acceptable. Add `asyncio.to_thread()` at the decoder layer if needed.

### Strict layer separation

The five layers (transport, framing, protocol, tamper, forge) are in separate modules and never import each other out of order. The relay does not know about protocols; the tamper controller does not know about network sockets; the forge engine does not know about live sessions.

**Tradeoff:** More files than a monolith. The payoff is that you can swap any layer (e.g. add a new framer, a new intercept backend, a SQLite storage layer) without touching unrelated code.

### Framing separated from protocol decoding

A framer finds *message boundaries* in the byte stream. A protocol decoder interprets *message content*. These are independent: you can frame without decoding (capture with an unknown protocol), swap framers without changing decoders, and add decoders later without touching the relay.

### ParsedField carries offset + size + raw bytes

Every `ParsedField` knows exactly where it lives in the original frame (`offset`, `size`, `raw_bytes`). This serves three purposes simultaneously: the hex-dump renderer can highlight each field's byte range in a distinct colour; the encoder can re-assemble bytes field-by-field when the operator edits a value; and nested structures (TLV entries, array items) are expressed as `children` on a parent field, matching the Wireshark tree model exactly.

### Encoder auto-recomputes length fields

When a variable-length field (e.g. `username`) is edited and re-encoded, the encoder walks the message definition looking for any other field whose `length` expression is `{username_len}` and recalculates that field's value from the encoded byte count. The operator edits `username`, not `username_len`.

### Safe expression evaluator

Length and count expressions (`"{total_length - 5}"`) are evaluated with Python's `eval()` on an AST that has been pre-validated to allow only arithmetic operators, name references, and a fixed whitelist of builtins (`min`, `max`, `abs`, `int`). Any other node type — attribute access, subscript, import, arbitrary call — raises `ValueError` before `eval()` runs.

### Textual TUI — container base for compose-only widgets

In Textual 8, custom widgets that use only `compose()` (no `render()`) must inherit from a container type (`Vertical`, `Horizontal`) rather than bare `Widget`. `Widget._render()` is part of Textual's visual pipeline and must not be overridden with application logic.

### EventBus → Textual message bridge

The proxy event callbacks run on asyncio and post internal `Message` subclasses onto Textual's message queue via `app.post_message()`. Textual processes these on the UI thread. This keeps the proxy core free of any Textual dependency while still delivering real-time updates to the UI.

### `is None` checks instead of `or` for optional parameters

`empty_registry or SessionRegistry()` silently creates a second registry because `SessionRegistry.__len__` returns `0` when empty, making an empty instance falsy. All optional dependency injection uses explicit `if x is not None else default` guards.

### In-memory frame storage by default

Frames are kept in `Session.frames` (a plain list) during the session. The `StorageBackend` interface exists for persistence but defaults to a no-op. This keeps the core simple and dependency-free.

### TLS MITM: certificate-per-session, not ssl= on a socket

For TLS interception the proxy must terminate TLS on both sides independently so the relay operates on plaintext bytes. Two-stage design:

1. **`protopoke/tls/ca.py`** — `CertificateAuthority` generates an RSA-2048 root CA on first run and persists it at `~/.protopoke/ca.crt`. For each target hostname it issues a short-lived leaf cert (RSA-2048, correct SAN for DNS or IP, signed by the CA, cached in-memory).
2. **`protopoke/tls/handler.py`** — `TLSHandler` builds `ssl.SSLContext` objects from those certs and passes them to `asyncio.start_server()` and `asyncio.open_connection()`. The relay, framing, and intercept layers see plaintext regardless of whether TLS is in use.

**Tradeoff:** TLS does not support TCP half-close (`write_eof()` raises `NotImplementedError` on `SSLTransport`). The relay's `_send_eof_to_dest()` guards with `can_write_eof()` before calling `write_eof()`.

---

## Roadmap

### Completed

- **TLS MITM** ✅ — auto-CA generation, per-session leaf certs, configurable upstream verify, manual cert override
- **Protocol definition DSL** ✅ — YAML/JSON; magic, sequence, and always match rules; rich field types; enum labels
- **Field-level tamper editing** ✅ — `modify_field_and_forward()` re-encodes with field name → value dict; length fields auto-recomputed
- **Field-level replay** ✅ — `replay_session_with_field_edits()` applies per-message-type field edits
- **Wireshark-style display** ✅ — `render_hexdump()` with ANSI highlights, `render_field_tree()`, `render_frame_header()`
- **Intercept / replace rules** ✅ — ordered, filterable, first-match-wins intercept rules; byte-pattern global replace rules
- **Terminal UI** ✅ — Textual TUI with Config, Traffic, Tamper, Forge, and Fuzzer tabs; project save/load
- **MCP server** ✅ — FastMCP wrapper exposing all ProxyAPI operations as AI tools
- **Fuzzing subsystem** ✅ — `FrameMutator` ABC; raw mutators (bit-flip, insert, delete, known-bad, radamsa, chain); protocol-aware mutators (field boundary, overflow, null-byte, length mangle); `FuzzerEngine` with baseline capture and anomaly detection; `api.fuzz_session()`; Fuzzer TUI tab (F5)

### Near term

- **SQLite persistence** — implement `SqliteStorageBackend` using `aiosqlite`. The `Frame` and `SessionInfo` dataclasses map directly to table rows with no schema redesign needed.

- **SNI-aware cert dispatch** — currently the proxy issues one leaf cert for `upstream_host` at startup. A full SNI callback would let the proxy issue a correctly-named cert for each unique `server_name` presented during the TLS handshake.

### Protocol layer

- **Protobuf / Thrift / Kaitai** — compile existing IDL schemas into `ProtocolDecoder` implementations. The interface (`decode(frame) -> ParsedMessage`) is simple enough to wrap any existing parser.

- **Protocol decoder library** — implement `ProtocolDecoder` subclasses for common protocols (e.g. HTTP/1.1, Redis, DNS) as built-in options alongside the definition-based approach.

### Advanced features

- **Differential replay** — replay the same session against two servers and compare responses frame-by-frame.

- **Timed replay** — honour original inter-frame delays from the captured session, or inject custom delays.

- **Plugin / dissector system** — load custom `Framer` or `ProtocolDecoder` subclasses from external Python modules at startup, without modifying the core package.
