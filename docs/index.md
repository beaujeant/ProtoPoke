# ProtoPoke

**A TCP / UDP / SOCKS5 proxy and protocol-analysis tool — Burp Suite for arbitrary binary protocols.**

ProtoPoke sits between a client and a server, captures every message that
crosses the wire, and lets you inspect, decode, modify, drop, replay, or
hand-craft traffic in real time. If you have ever wanted "Burp Suite, but for
a custom binary game protocol" — that is ProtoPoke.

---

## What it does

- **Proxies any connection** — each forwarder is a plain **TCP** proxy, a
  **UDP** proxy (per-client-tuple flows), or a **SOCKS5** proxy that learns
  its upstream target from the SOCKS handshake. Run many forwarders and many
  concurrent sessions at once.
- **Intercepts frames live** — pause messages mid-stream, inspect them, edit
  the raw bytes or named protocol fields, then forward or drop them.
- **Decodes binary protocols** — describe a protocol in a YAML/JSON
  definition and frames are parsed into named, typed fields with a
  Wireshark-style hex + tree view.
- **Rewrites traffic automatically** — ordered replace rules (binary pattern,
  regex, or custom Python script) transform frames as they flow through.
- **Forges and replays** — hand-craft frames from scratch, replay captured
  sessions (optionally with field edits), or build reusable playbooks.
- **Half-open sessions** — when one peer disconnects, ProtoPoke keeps the
  other side open (`only server` / `only client`) so you can keep driving
  the live connection from Forge.
- **TLS / MITM** — auto-generated root CA and per-session certificates let
  ProtoPoke decrypt, modify, and re-encrypt TLS traffic.
- **AI-controllable** — an embedded MCP server exposes every proxy operation
  as a tool, so an AI assistant can drive the same session you see on screen.

Fuzzing is also available but **experimental** — see
[Fuzzing](reference/fuzzing.md).

---

## Two ways to use it

ProtoPoke has one engine and two front ends. Pick whichever fits the task —
they share the same concepts, so the docs are split into two parallel tracks.

| | **User Interface** | **Core Library** |
|---|---|---|
| What | A full terminal UI (Textual) with Config, Traffic, Intercept, Forge, Fuzzer, and Logs tabs. | The `ProtoPokeAPI` Python class — the single façade for scripting and automation. |
| Best for | Interactive exploration, manual reverse engineering. | Automated tests, repeatable workflows, integration into other tools. |
| Start here | [User Interface → Getting Started](ui/getting-started.md) | [Core Library → Getting Started](core/getting-started.md) |

Both tracks cover the same four areas — **Config**, **Traffic**,
**Intercept**, and **Forge** — and both lean on the shared
[Reference](reference/framers.md) pages (framers, protocol definitions,
custom replace scripts) and worked [Guides](guides/dns.md).

---

## Who is this for?

Security researchers, reverse engineers, and developers who work with custom
binary network protocols. ProtoPoke prioritises **readability,
extensibility, and hackability** over raw throughput.

---

## Quick links

- [Installation](installation.md)
- [User Interface — Getting Started](ui/getting-started.md)
- [Core Library — Getting Started](core/getting-started.md)
- [Protocol Definition reference](reference/protocol-definitions.md)
- [DNS guide](guides/dns.md)
- [MCP Server](mcp/overview.md)
