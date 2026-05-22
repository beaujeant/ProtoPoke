---
title: "Guide: DNS"
---

This guide is a worked example that ties together the three customisation
points ProtoPoke gives you, using DNS as the target protocol:

1. A **custom framer** — how to cut a byte stream into DNS messages.
2. A **protocol definition** — how to decode a DNS message into named fields.
3. A **custom replace script** — how to rewrite every A-record answer to
   `127.0.0.1`.

All three artifacts ship with the repo under `examples/`, so you can follow
along without writing anything from scratch.

DNS is a good teaching protocol: it is well documented (RFC 1035), one
query/response per message, and `dig` is a handy traffic generator.

---

## 1. The framer

Each DNS message is exactly one UDP datagram. There is no length prefix; 
the datagram boundary *is* the message boundary. A ProtoPoke 
**UDP forwarder uses the `raw` framer** (one datagram = one frame) and 
you write **no framer code at all**.

---

## 2. The protocol definition — decoding a DNS message

Once frames are aligned to message boundaries, a **protocol definition**
turns the raw bytes into named, typed fields. The repo ships one for DNS over
UDP:
[`examples/protocols/dns.proto.yaml`](https://github.com/beaujeant/protopoke/blob/main/examples/protocols/dns.proto.yaml).

It is a YAML file describing the DNS message layout. The fixed 12-byte
header is straightforward:

```yaml
protocol:
  name: "DNS"
  endianness: big        # all DNS integers are big-endian
  messages:
    - name: "QueryRD"
      direction: client_to_server
      match:
        type: magic
        offset: 2          # first byte of the Flags field
        value: "0x01"      # QR=0, OPCODE=0, RD=1 — a normal dig query
      fields:
        - { name: id, type: uint16, display: hex }
        - name: flags
          type: bitfield
          length: 2
          bits: { 15: qr, 8: rd, 7: ra, 3: rcode_3, 2: rcode_2, 1: rcode_1, 0: rcode_0 }
        - { name: qdcount, type: uint16 }
        - { name: ancount, type: uint16 }
        - { name: nscount, type: uint16 }
        - { name: arcount, type: uint16 }
        - name: questions          # repeats qdcount times
          type: array
          array:
            count: "{qdcount}"
            item:
              - { name: qname,  type: string, null_terminated: true, encoding: ascii }
              - { name: qtype,  type: uint16, display: enum, enum: { 1: "A", 28: "AAAA" } }
              - { name: qclass, type: uint16, display: enum, enum: { 1: "IN" } }
        - { name: extra_sections, type: bytes, length: -1, display: hex }
```

What this demonstrates about the DSL:

- **`match`** picks which definition applies to a frame. DNS cannot be
  matched on a single bit, so the example uses `magic` byte matches over the
  flags byte (`0x00`/`0x01` for queries, `0x80`/`0x81` for responses) plus an
  `always` catch-all at the end.
- **`bitfield`** breaks the 16-bit flags word into named bits (`qr`, `rd`,
  `ra`, `rcode_*`).
- **`array`** with `count: "{qdcount}"` iterates a sub-structure a
  field-driven number of times — so multi-question queries decode correctly.
- **DSL limits** — DNS label compression and per-RR-type RDATA layouts cannot
  be expressed in the DSL, so the variable parts (`extra_sections`, `rdata`)
  are kept as raw `bytes` and you cross-reference the colour-coded hex dump.
  This is normal: a definition is built up iteratively, and "raw bytes here"
  is a perfectly good intermediate state.

Load it via *Config → Protocol Definition*, or
`protocol_definition_path="examples/protocols/dns.proto.yaml"`. The full
field-type and matcher reference is in
[Protocol Definitions](/reference/protocol-definitions).

---

## 3. The custom replace script — rewriting A records to 127.0.0.1

Goal: every A-record answer should resolve to `127.0.0.1`, so a client talks
to a local server you control regardless of what hostname it looked up.

### Why a binary or regex rule is not enough

The obvious approach is a **binary replace rule**: match the four answer
bytes and substitute `7F 00 00 01`. It works for one specific IP and breaks
immediately otherwise:

- It only matches the literal bytes you typed — a different answer IP is
  untouched.
- The same four bytes can appear *anywhere* — inside a TTL, a transaction
  ID, a label length — and a binary rule rewrites them blindly, corrupting
  the message.
- Refining the pattern (e.g. match `00 04` RDLENGTH then 4 wildcards) just
  moves the problem: `00 04` also occurs inside other records.

The pattern languages are blind to **structure**. A nested,
length-prefixed binary format needs real parsing — which is exactly what a
**script rule** gives you.

### The script

The repo ships
[`examples/scripts/dns_a_to_localhost.py`](https://github.com/beaujeant/protopoke/blob/main/examples/scripts/dns_a_to_localhost.py).
It exports the one function every replace script must define:

```python
def apply(data: bytes, variables: dict) -> bytes:
    ...
```

It walks the DNS message properly — skips the 12-byte header, steps over the
question section, then iterates the answer/authority/additional records — and
overwrites RDATA **only** where `TYPE=A (1)`, `CLASS=IN (1)`, and
`RDLENGTH=4`. AAAA, CNAME, MX, NS, the question section, and compression
pointers are all left untouched.

Add it as a **Custom script** replace rule:

| Field | Value |
|-------|-------|
| Label | `DNS A → 127.0.0.1` |
| Type | `Custom script` |
| Script path | `examples/scripts/dns_a_to_localhost.py` |
| Direction | `server → client` |
| Scope | `Traffic` only |

The `apply()` contract, the shared `variables` store, and auto-reload are
documented in [Custom Replace Scripts](/reference/replace-scripts).

---

## Putting it together — a UDP walkthrough

1. **Forwarder** — *Config* tab → add a **UDP** forwarder: listen
   `127.0.0.1:5353`, upstream `1.1.1.1:53`, framer `raw` (default), protocol
   definition `examples/protocols/dns.proto.yaml`. Start it.
2. **Generate traffic** — `dig @127.0.0.1 -p 5353 example.com`.
3. **Inspect** — on the *Traffic* tab, select the query/response frames and
   toggle the parsed view: `id`, `flags`, the bit-broken `flags_decoded`,
   the counts, and the `questions` array.
4. **Intercept** — on the *Intercept* tab, enable intercept for client→server
   and re-run `dig`; the query is held so you can edit a field (try changing
   `qdcount`) before forwarding.
5. **Rewrite** — add the `dns_a_to_localhost.py` script rule above and re-run
   `dig` against several names — they all answer `127.0.0.1`, while an
   `AAAA` query is left alone because it has no A records.
6. **Verify** — back on *Traffic* you will see the original frame *and* a
   `framer_name=tamper` frame: the rewritten datagram ProtoPoke actually
   sent. The unmodified frame is always preserved for inspection.

## Where next

- [Framers](/reference/framers) — the full custom-framer reference
- [Protocol Definitions](/reference/protocol-definitions) — every field type and matcher
- [Custom Replace Scripts](/reference/replace-scripts) — the `apply()` API in depth
- [SSH-BPP guide](/guides/ssh-bpp) — a second worked example *(in progress)*
