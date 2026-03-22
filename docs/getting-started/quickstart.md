# Quick Start

This guide walks you through a basic ProtoPoke session: proxy a TCP connection, observe traffic, and intercept a frame.

## 1. Launch the TUI

```bash
protopoke
```

The terminal UI opens with six tabs. You start on the **Config** tab.

## 2. Configure the Proxy

In the **Config** tab, set:

- **Listen Host**: `127.0.0.1`
- **Listen Port**: `8080`
- **Upstream Host**: the IP or hostname of your target server
- **Upstream Port**: the port your target listens on

Click **Start** to begin proxying.

## 3. Connect a Client

Point your client application at `127.0.0.1:8080` instead of the real server. ProtoPoke forwards traffic transparently.

## 4. Observe Traffic

Switch to the **Traffic** tab (++f2++). You will see:

- A list of active and closed sessions
- Select a session to see its frames
- Select a frame to see hex dump and parsed field details

## 5. Intercept and Modify

Switch to the **Tamper** tab (++f3++) and enable tamper mode. New frames are held in a queue where you can:

- **Forward** — send the frame as-is
- **Drop** — silently discard the frame
- **Modify** — edit the raw bytes or individual protocol fields, then forward

## 6. Forge a Frame

Switch to the **Forge** tab (++f4++). Type hex bytes in the editor and send them directly to the target. From the Traffic tab, you can also right-click any captured frame and send it to Forge.

## What Next?

- [Set up framing](../guide/framing.md) so frames align with protocol message boundaries
- [Write a protocol definition](../guide/protocol-definitions.md) to decode frames into named fields
- [Use the MCP server](../mcp/overview.md) to let an AI assistant control the proxy
- [Script with the Python API](../api/usage.md) for automation
