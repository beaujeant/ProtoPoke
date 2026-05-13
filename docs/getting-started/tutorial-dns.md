# Tutorial: Proxying DNS over UDP

This tutorial walks you through a complete ProtoPoke workflow against a
real protocol: **DNS over UDP**. By the end you will have:

- A UDP forwarder that intercepts traffic between `dig` and `1.1.1.1:53`.
- A protocol definition that decodes DNS headers into named fields.
- A live intercept that lets you edit a query before it reaches the server.
- A naive replace rule, a discussion of *why it is wrong*, and a correct
  script-based rule that rewrites every A-record response to `127.0.0.1`.

DNS is a good first protocol to explore: it is well-documented (RFC 1035),
one query/response per UDP datagram, and `dig` is a quick generator.

## Prerequisites

- ProtoPoke installed (`pip install -e ".[dev]"` from the repo root).
- `dig` (Linux: `apt install dnsutils`; macOS: ships with the system).
- Outbound UDP to `1.1.1.1:53` from your machine.

## 1. Launch ProtoPoke

```bash
protopoke
```

You land on the **Config** tab. The default forwarder is a TCP one — we
will replace it with a UDP forwarder.

## 2. Configure the UDP forwarder

In the Config tab, **Edit** the default forwarder (or add a new one) and
set:

| Field                | Value                                   |
| -------------------- | --------------------------------------- |
| Name                 | `DNS`                                   |
| Type                 | `UDP`                                   |
| Listen Host          | `127.0.0.1`                             |
| Listen Port          | `5353` (any unprivileged port works)    |
| Upstream Host        | `1.1.1.1`                               |
| Upstream Port        | `53`                                    |
| Framer               | `raw` (default — each datagram = one frame) |
| Protocol Definition  | `examples/protocols/dns.proto.yaml`     |

Save and click **Start**. The forwarder is now listening.

!!! tip
    Port `5353` is what `mDNS` traditionally uses but nothing is bound
    to it on a clean Linux box. Any free port above 1024 works — you do
    not need root.

## 3. Generate traffic with `dig`

In another terminal:

```bash
dig @127.0.0.1 -p 5353 example.com
```

You should see a normal `dig` answer (`93.184.216.34` at the time of
writing). ProtoPoke has transparently relayed your query to `1.1.1.1`
and the response back to `dig`.

## 4. Observe the traffic

Switch to the **Traffic** tab (++f2++). You will see one session listing
two frames:

- **client → server** — the DNS query
- **server → client** — the DNS response

Select either frame. The right pane shows:

- The hex dump with per-field colouring.
- A **tree view** of the parsed message: `id`, `flags`,
  `flags_decoded` (bitfield with named bits), `qdcount`, `ancount`, …,
  and the raw `sections` blob.

The frame is matched against one of the `messages:` entries in
`dns.proto.yaml`. For a `dig` query you will see **QueryRD** (RD bit
set); the answer will be **ResponseRA** (RA bit set).

!!! note
    The variable-length sections (question, answer, …) are kept as raw
    bytes because DNS label encoding and resource records cannot be
    expressed in the DSL. The hex dump is colour-coded so you can still
    pick out the qname.

## 5. Intercept and modify a query

Switch to the **Tamper** tab (++f3++) and **enable tamper mode** for the
client → server direction. Re-run:

```bash
dig @127.0.0.1 -p 5353 example.com
```

`dig` now hangs because the query is held in the queue. In the Tamper
tab you have three choices for each pending frame:

- **Forward** — release it unchanged.
- **Drop** — discard it (`dig` will time out).
- **Modify** — edit the bytes or the parsed fields.

Click **Modify**, expand the parsed tree, and change `qdcount` from `1`
to `2`. Forward. The frame becomes structurally invalid — `1.1.1.1` will
respond with a `FORMERR` (RCODE=1) which you can verify by inspecting
the response back in the Traffic tab.

Disable tamper before continuing.

## 6. A replace rule, the naive way

Goal: every A-record answer should resolve to `127.0.0.1` so a client
talks to a local server you control, regardless of the hostname it
looked up.

Start with the obvious approach. Run a query first to see what comes
back:

```bash
dig @127.0.0.1 -p 5353 one.one.one.one
```

`1.1.1.1` answers with `1.1.1.1` (yes, really). Open **Tamper → Add
Replace Rule** and configure:

| Field         | Value                            |
| ------------- | -------------------------------- |
| Label         | `1.1.1.1 → 127.0.0.1 (naive)`    |
| Type          | `Binary pattern replacement`     |
| Pattern (hex) | `01 01 01 01`                    |
| Replacement   | `7F 00 00 01`                    |
| Direction     | `server → client`                |
| Apply to      | `traffic` only                   |

Re-run the `dig` and you will see `127.0.0.1` in the answer.

**Now try a different name:**

```bash
dig @127.0.0.1 -p 5353 example.com
```

You still get `93.184.216.34`. The rule only matched the literal four
bytes `01 01 01 01`.

**It gets worse.** Add a query whose name encoding contains
`01 01 01 01` by coincidence — or imagine a TTL or transaction ID that
happens to be `01 01 01 01`. A naive binary rule has no idea what those
bytes *mean*; it just substitutes blindly. You could end up corrupting
RDLENGTHs, label lengths, or TXIDs, producing garbled responses or
`dig` timeouts.

You could try harder regex tricks — for example matching `00 04`
(RDLENGTH=4) followed by 4 wildcard bytes — but `00 04` also appears
inside other resource records, OPT pseudo-records, and within question
sections. Every refinement has a counter-example. The pattern language
is not expressive enough for nested-length-prefixed binary structures.

**Disable the naive rule** before moving on.

## 7. The correct approach: a script rule

ProtoPoke replace rules support a third type, **Custom script**, where
you point at a Python file that exports
`apply(data: bytes, variables: dict) -> bytes`. The script can do
anything Python can — including correctly parsing the DNS message.

The repo ships one ready to use:
[`examples/scripts/dns_a_to_localhost.py`](https://github.com/beaujeant/protopoke/blob/main/examples/scripts/dns_a_to_localhost.py).
It walks the question section, then iterates the answer, authority, and
additional sections, and overwrites RDATA *only* for records where
`TYPE=A (1)` and `CLASS=IN (1)` and `RDLENGTH=4`. AAAA, CNAME, MX, NS,
and the question section are all left untouched. Compression pointers
are handled.

Add it in **Tamper → Add Replace Rule**:

| Field         | Value                                                  |
| ------------- | ------------------------------------------------------ |
| Label         | `DNS A → 127.0.0.1`                                    |
| Type          | `Custom script`                                        |
| Script path   | `<repo>/examples/scripts/dns_a_to_localhost.py`        |
| Direction     | `server → client`                                      |
| Apply to      | `traffic` only                                         |

Re-run:

```bash
dig @127.0.0.1 -p 5353 example.com
dig @127.0.0.1 -p 5353 one.one.one.one
dig @127.0.0.1 -p 5353 google.com
dig @127.0.0.1 -p 5353 AAAA google.com
```

The first three all answer `127.0.0.1`. The AAAA query is left untouched
because it has no A records — the script only rewrites what it should.

## 8. Verify with the Traffic tab

Open Traffic for any of the A-record sessions. You will see **two**
server → client frames:

1. The original frame from `1.1.1.1` (real IP in RDATA).
2. A `framer_name=tamper` frame — the rewritten datagram that ProtoPoke
   actually sent to `dig`.

This is by design: the unmodified frame is preserved for inspection
even when a replace rule fires. You can diff the two side by side in
the hex view.

## What you have learned

- UDP forwarding with the default raw framer (one datagram = one frame).
- Attaching a YAML protocol definition to a forwarder for symbolic field
  decoding.
- Live interception (forward / drop / modify).
- The limits of pattern-based replace rules for nested-length-prefixed
  protocols.
- Script-type replace rules for cases where you need real parsing.

## Where to go next

- [Protocol Definitions](../guide/protocol-definitions.md) — the full
  field-type and matcher reference if you want to split `sections`
  into named subfields for one specific RR type.
- [Tamper & Intercept](../guide/tamper.md) — intercept rules, scopes,
  and the shared variable store.
- [Forge & Replay](../guide/forge.md) — replay a captured DNS query
  with modified fields, useful when you want to fuzz a single field.
- [Fuzzing](../guide/fuzzing.md) — run mutators against the question
  section to see how `1.1.1.1` handles malformed labels.
