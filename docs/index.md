# ProtoPoke

**A TCP / UDP / SOCKS5 proxy and protocol analysis tool — Burp Suite for arbitrary binary protocols.**

ProtoPoke intercepts any TCP, UDP, or SOCKS5-proxied connection and lets you inspect, modify, or drop individual frames in real time. Load a YAML protocol definition and frames are automatically decoded into named fields with a Wireshark-style hex + tree view. Replay captured sessions, fuzz protocols with pluggable mutators, or let an AI assistant drive the entire workflow through MCP.

---

## Key Features

- **TCP / UDP / SOCKS5 forwarders** — each forwarder picks a transport: a plain TCP proxy, a UDP proxy (per-client-tuple flows), or a SOCKS5 proxy that discovers the upstream target from the SOCKS handshake. Run many forwarders and many concurrent sessions at once.
- **Half-open session handling** — when one side disconnects, the other stays open by default (`only server` / `only client` state) so you can keep driving the live connection from Forge
- **TLS/SSL MITM** — auto-generated root CA and per-session certificates; clients trust the CA once, proxy decrypts transparently
- **Intercept queue** — pause frames mid-stream, inspect, modify, forward, or drop them live
- **Protocol definition DSL** — describe any binary protocol in YAML or JSON; frames are decoded into named, typed fields automatically
- **Wireshark-style display** — hex dump with per-field colour highlights and a nested field tree
- **Forge** — hand-craft frames and send them directly to the target, or inject into a live proxy/forge session
- **Session replay** — replay captured sessions with optional per-field edits
- **Fuzzing** — replay-based fuzzing with built-in and protocol-aware mutators, automatic anomaly detection
- **Rules engine** — ordered replace rules (binary/regex/script) and intercept filter rules
- **Terminal UI** — full Textual-based interface with Config, Traffic, Tamper, Forge, Fuzzer, and Logs tabs
- **MCP server** — expose 70+ proxy operations as AI tools via the Model Context Protocol
- **Python API** — programmatic control through `ProtoPokeAPI` for scripting and automation
- **Project system** — save and load proxy configurations, rules, forge playbooks, captured traffic, and display filters as `.pp` ZIP files

---

## Who Is This For?

ProtoPoke is designed for security researchers, reverse engineers, and developers who work with custom binary TCP protocols. It prioritises **readability, extensibility, and hackability** over throughput.

---

## Quick Links

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [MCP Server Setup](mcp/overview.md)
- [Protocol Definition Guide](guide/protocol-definitions.md)
- [Python API](api/usage.md)
