"""
Replace-rule script: rewrite every DNS A-record answer to 127.0.0.1.

Use case
--------
You are proxying DNS through ProtoPoke and want every A-record reply to
point at localhost — for instance, to force a client to talk to a local
HTTP server you control regardless of which hostname it looks up.

Hook this script up as a ``script``-type ReplaceRule on the
server_to_client direction. ProtoPoke calls ``apply(data, variables)``
once per frame; the function returns the rewritten datagram.

Why a script, not a regex
-------------------------
A naive byte-level regex (e.g. "find any 4-byte sequence and replace
with 7F 00 00 01") would corrupt unrelated fields — transaction IDs,
label-length prefixes, TTLs, compression pointers, RDLENGTHs, AAAA
addresses, and so on.

DNS responses carry the IPv4 you want to rewrite in a *specific* place:
the RDATA of a resource record whose TYPE=1 (A) and CLASS=1 (IN) and
RDLENGTH=4. This script parses the message structure correctly and only
touches those four bytes per A record. Everything else — including
AAAA, CNAME, MX, NS records and the question section — is left
untouched.

Configure as a ReplaceRule
--------------------------
TUI: Tamper tab → Add Replace Rule → Type: script → Script path:
``/path/to/examples/scripts/dns_a_to_localhost.py`` → Direction:
server_to_client → Apply to: traffic.

Python API::

    from protopoke.models import Direction
    from protopoke.rules.rule import ReplaceRule

    api.add_replace_rule(ReplaceRule.create(
        label="DNS A → 127.0.0.1",
        pattern_str="",
        replacement=b"",
        rule_type="script",
        script_path="/path/to/examples/scripts/dns_a_to_localhost.py",
        direction=Direction.SERVER_TO_CLIENT,
        apply_to_traffic=True,
        apply_to_tamper=False,
        apply_to_forge=False,
    ))
"""

from __future__ import annotations

import struct

_LOCALHOST = bytes((127, 0, 0, 1))
_TYPE_A    = 1
_CLASS_IN  = 1


def _skip_name(data: bytes, offset: int) -> int:
    """
    Advance ``offset`` past a DNS name encoded at ``data[offset:]``.

    DNS names are a sequence of length-prefixed labels terminated either by
    a zero byte or by a 2-byte compression pointer (top two bits set,
    0b11xxxxxx). Returns the offset of the first byte *after* the name, or
    ``len(data)`` if the encoding runs off the end of the buffer (which
    signals a malformed message — the caller should abort).
    """
    n = len(data)
    while offset < n:
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2  # compression pointer is always 2 bytes total
        offset += 1 + length
    return n  # ran off the end — caller will detect and abort


def apply(data: bytes, variables: dict) -> bytes:
    """
    Rewrite every A-record RDATA in a DNS message to 127.0.0.1.

    Returns the modified bytes, or the original ``data`` unchanged if the
    message is too short to be a DNS header or its record structure does
    not parse cleanly.
    """
    if len(data) < 12:
        return data

    qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHH", data, 4)
    total_rrs = ancount + nscount + arcount
    if total_rrs == 0:
        return data  # query or empty response — nothing to rewrite

    out = bytearray(data)
    offset = 12

    # Skip the Question section: each entry is name + QTYPE(2) + QCLASS(2).
    for _ in range(qdcount):
        offset = _skip_name(out, offset)
        offset += 4
        if offset > len(out):
            return data

    # Walk Answer / Authority / Additional sections, rewriting A records.
    rewrites = 0
    for _ in range(total_rrs):
        offset = _skip_name(out, offset)
        if offset + 10 > len(out):
            return data
        rrtype, rrclass, _ttl, rdlength = struct.unpack_from(">HHIH", out, offset)
        rdata_start = offset + 10
        rdata_end   = rdata_start + rdlength
        if rdata_end > len(out):
            return data
        if rrtype == _TYPE_A and rrclass == _CLASS_IN and rdlength == 4:
            out[rdata_start:rdata_end] = _LOCALHOST
            rewrites += 1
        offset = rdata_end

    if rewrites > 0:
        # Stash the count so other rules / playbooks can read it via the
        # shared variable store. Purely optional.
        variables["dns_a_rewrites"] = variables.get("dns_a_rewrites", 0) + rewrites

    return bytes(out)


# ---------------------------------------------------------------------------
# Smoke-test — run directly: python dns_a_to_localhost.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # A real response captured by dig for "example.com A" against 1.1.1.1:
    #   header: id=0x1234 flags=0x8180 QD=1 AN=1 NS=0 AR=0
    #   qname:  example.com (07 'example' 03 'com' 00)
    #   qtype:  A (0x0001) qclass: IN (0x0001)
    #   answer: name compression pointer to offset 12 (C0 0C)
    #           type=A class=IN ttl=300 rdlength=4 rdata=93.184.216.34
    response = bytes.fromhex(
        "1234818000010001000000000765" "78616d706c6503636f6d0000010001"
        "c00c000100010000012c0004" "5db8d822"
    )

    rewritten = apply(response, {})

    # The four RDATA bytes are at the very end of the message.
    assert rewritten[-4:] == _LOCALHOST, \
        f"RDATA not rewritten: got {rewritten[-4:].hex()}"
    # Everything before RDATA must be identical to the original.
    assert rewritten[:-4] == response[:-4], "non-RDATA bytes were touched"

    # A response with no A records (e.g. an AAAA-only reply) must be untouched.
    aaaa_response = bytes.fromhex(
        "1234818000010001000000000765" "78616d706c6503636f6d00001c0001"
        "c00c001c00010000012c0010" "26000020000000000000000000000001"
    )
    assert apply(aaaa_response, {}) == aaaa_response, "AAAA record was modified"

    # A query (ANCOUNT=0) must be untouched.
    query = bytes.fromhex(
        "12340100000100000000000007" "6578616d706c6503636f6d0000010001"
    )
    assert apply(query, {}) == query, "query was modified"

    # A truncated / malformed message must be returned unchanged.
    assert apply(b"\x00", {}) == b"\x00"

    print("All tests passed.")
