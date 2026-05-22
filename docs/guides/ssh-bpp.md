---
title: "Guide: SSH Binary Packet Protocol"
---

!!! note "In progress"

    This guide is a placeholder. It will document the SSH Binary Packet
    Protocol (BPP) exercise built for ProtoPoke. The outline below is the
    intended structure — content to follow.

The SSH transport layer wraps everything above it in the **Binary Packet
Protocol** (RFC 4253 §6): each packet carries a length, a padding length,
a payload, random padding, and — once a key exchange completes — a MAC.
That makes it a good second worked example after the [DNS guide](dns.md),
because it exercises the same three customisation points against a more
involved, partly-encrypted protocol.

## Planned contents

### 1. The framer — SSH BPP packetisation

- The `packet_length` / `padding_length` / `payload` / `padding` / `MAC`
  layout and how to cut the TCP stream into packets.
- Handling the initial plaintext identification string exchange
  (`SSH-2.0-...\r\n`) before BPP framing kicks in.
- What changes once encryption is negotiated (length is no longer in the
  clear).

### 2. The protocol definition — decoding a BPP packet

- Decoding `packet_length`, `padding_length`, the message-type byte, and the
  payload.
- An enum for the SSH message numbers (`SSH_MSG_KEXINIT`, `SSH_MSG_NEWKEYS`,
  …).
- DSL limits: where decoding stops once the payload is encrypted.

### 3. A custom replace/inspect script

- A script-type rule that inspects or tweaks the plaintext handshake
  packets.

### 4. Walkthrough

- Setting up the forwarder, capturing a handshake, and stepping through it.

## Where next

- [DNS guide](dns.md) — the completed worked example
- [Framers](../reference/framers.md)
- [Protocol Definitions](../reference/protocol-definitions.md)
- [Custom Replace Scripts](../reference/replace-scripts.md)
