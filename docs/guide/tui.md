# Terminal UI

ProtoPoke provides a full terminal interface built with [Textual](https://textual.textualize.io/).

## Launching

```bash
protopoke
```

Or run directly:

```bash
python -m protopoke.ui.app
```

## Tabs

| Tab | Shortcut | Purpose |
|-----|----------|---------|
| **Config** | ++f1++ | Configure listener, upstream server, TLS, framing, and protocol definition. Start/stop the proxy. |
| **Traffic** | ++f2++ | Live session list, frame list, hex dump, and parsed field detail view. Send any frame to Forge. |
| **Tamper** | ++f3++ | Intercept queue: forward, drop, or modify frames. Manage intercept rules and global replace rules. |
| **Forge** | ++f4++ | Hand-craft frames in a hex editor and send them to the target. Full send history. |
| **Fuzzer** | ++f5++ | Select a captured session, pick mutators, run a fuzzing campaign, review results with anomaly flags. |
| **Logs** | ++f6++ | Application log output. |

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| ++f1++ – ++f6++ | Switch tabs |
| ++ctrl+n++ | New project |
| ++ctrl+o++ | Open project |
| ++ctrl+s++ | Save project |
| ++ctrl+shift+s++ | Save project as... |
| ++ctrl+q++ | Quit |
| ++ctrl+f++ | Send selected frame to Forge |

## Config Tab

The Config tab is where you manage forwarders before starting them. Each
forwarder is edited in a modal with:

- **Type** — `TCP`, `UDP`, or `SOCKS5`. The form adapts to the choice:
  UDP and SOCKS5 hide the TLS-listen option, UDP locks the framer to `raw`,
  and SOCKS5 shows username/password auth fields instead of an upstream
  host/port (the target comes from each client's SOCKS handshake).
- **Listener settings** — bind address and port
- **Upstream settings** — target host and port (TCP/UDP only)
- **TLS** — enable TLS termination on the client side (MITM) and/or TLS to the upstream (TCP only)
- **Framing** — select a framer (raw, delimiter, length_prefix, line) and configure its parameters, or load a custom framer script
- **Protocol definition** — path to a YAML/JSON file for protocol decoding

Multiple forwarders can be configured to proxy several targets — and several
transports — simultaneously. The Config tab also hosts the embedded MCP
server controls (enable switch, host, port).

## Traffic Tab

The Traffic tab provides a three-panel view:

1. **Session list** — all active and closed sessions with metadata (source, destination, state, frame count)
2. **Frame list** — frames for the selected session, showing direction, size, sequence number, and timestamp
3. **Detail panel** — hex dump with per-field colour highlights and a parsed field tree (when a protocol definition is loaded)

## Tamper Tab

When tamper mode is enabled, frames are held in a queue before being forwarded. The Tamper tab lets you:

- View all pending intercepted frames
- Forward, drop, or modify individual frames
- Edit raw bytes or named protocol fields
- Manage ordered **intercept rules** that control which frames are held
- Manage **replace rules** that automatically rewrite byte patterns

## Forge Tab

The Forge tab is a hex editor for constructing frames from scratch:

- Type raw hex bytes
- Send directly to the upstream target
- Review the full send/response history
- Any captured frame from the Traffic tab can be sent to Forge for editing

## Fuzzer Tab

The Fuzzer tab runs mutation-based fuzzing campaigns against captured sessions:

1. Select a captured session as the baseline
2. Choose mutators (bit flip, byte insert, known bad values, protocol-aware mutators, etc.)
3. Configure iteration count and stopping conditions
4. Run the campaign and review results with crash/anomaly indicators
