"""
Example custom framer: DNS over TCP (RFC 1035 §4.2.2).

Wire format
-----------
DNS over TCP wraps every DNS message in a 2-byte big-endian length prefix.
The prefix counts only the DNS message bytes — it does NOT include itself.

    +--------+--------+
    | LENGTH (2 bytes)|   big-endian uint16
    +--------+--------+
    |                 |
    |   DNS message   |   LENGTH bytes
    |                 |
    +-----------------+

Minimum valid DNS message: 12 bytes (the fixed DNS header, no records).
Maximum: 65 535 bytes (fits in uint16; in practice responses are far smaller).

Usage in ProtoPoke
------------------
Config tab → Edit Framer → Custom, then set:

  Script path : /path/to/examples/dns_framer.py

That is all.

How a custom framer works
--------------------------
A custom framer is two plain functions — no class, no imports from ProtoPoke:

    def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
        ...

    def on_flush(state: dict, direction: str) -> list[bytes]:
        ...

``state`` is a plain dict that is created once per proxied connection and
passed to every call for **both** directions.  This means cross-direction
state is trivially possible: whatever you store under a key in one direction
is readable in the other.

``direction`` is the string ``"c2s"`` (client → server) or ``"s2c"``
(server → client).  Use it to keep per-direction buffers separate:

    buf = state.setdefault(direction, bytearray())

For a correlated protocol (server response depends on client command):

    def on_data(data, state, direction):
        buf = state.setdefault(direction, bytearray())
        buf.extend(data)
        if direction == "c2s":
            state["last_cmd"] = ...      # record for response parsing
        else:
            cmd = state.get("last_cmd")  # read what the client sent
            ...
"""

from __future__ import annotations

import struct

# DNS message constants
_DNS_MIN_MSG = 12   # minimum valid DNS payload (fixed 12-byte header)
_PREFIX_LEN  = 2    # TCP length prefix is always 2 bytes


def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    """
    Accumulate *data* and return complete DNS-over-TCP message chunks.

    Uses ``state[direction]`` as the per-direction accumulation buffer.
    Each returned ``bytes`` value contains the 2-byte length prefix followed
    by the DNS message — exactly the bytes that appeared on the wire.

    Desync recovery: if the declared length is implausible the entire buffer
    is emitted as a raw chunk and parsing restarts on the next data arrival.
    """
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    frames: list[bytes] = []

    while len(buf) >= _PREFIX_LEN:
        (msg_len,) = struct.unpack_from(">H", buf, 0)

        if msg_len < _DNS_MIN_MSG or msg_len > 0xFFFF:
            # Implausible length — desynced.  Flush and restart.
            frames.append(bytes(buf))
            buf.clear()
            break

        total = _PREFIX_LEN + msg_len
        if len(buf) < total:
            break  # incomplete — wait for more data

        frames.append(bytes(buf[:total]))
        del buf[:total]

    return frames


def on_flush(state: dict, direction: str) -> list[bytes]:
    """
    Emit any remaining buffered bytes when the connection closes.

    If a DNS message arrived incomplete (e.g. the sender crashed
    mid-transmission), whatever bytes were buffered are still returned
    so nothing is silently discarded.
    """
    buf = state.pop(direction, bytearray())
    return [bytes(buf)] if buf else []


# ---------------------------------------------------------------------------
# Smoke-test (run directly: python dns_framer.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    DIR = "c2s"
    state: dict = {}

    def _wrap(dns_msg: bytes) -> bytes:
        return struct.pack(">H", len(dns_msg)) + dns_msg

    # Minimal 12-byte DNS query header
    _QUERY_HEADER = bytes([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags: recursion desired
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x00,  # ANCOUNT = 0
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
    ])
    _FULL_QUERY = _QUERY_HEADER + b"\x07example\x03com\x00\x00\x01\x00\x01"

    frame_a = _wrap(_QUERY_HEADER)
    frame_b = _wrap(_FULL_QUERY)

    # Test 1: single frame split across two feeds
    half = len(frame_a) // 2
    assert on_data(frame_a[:half], state, DIR) == [], "T1a: should buffer partial frame"
    result = on_data(frame_a[half:], state, DIR)
    assert len(result) == 1 and result[0] == frame_a, f"T1b failed: {result}"

    # Test 2: two back-to-back frames in one feed
    state.pop(DIR, None)
    result = on_data(frame_a + frame_b, state, DIR)
    assert len(result) == 2 and result[0] == frame_a and result[1] == frame_b, f"T2 failed"

    # Test 3: desync — declared length too small for a valid DNS message
    state.pop(DIR, None)
    bad = struct.pack(">H", 3)
    result = on_data(bad, state, DIR)
    assert len(result) == 1 and result[0] == bad, f"T3a: desync frame mismatch"
    result = on_data(frame_a, state, DIR)
    assert len(result) == 1 and result[0] == frame_a, f"T3b: post-desync frame mismatch"

    # Test 4: flush emits a partial frame
    state.pop(DIR, None)
    assert on_data(frame_a[:5], state, DIR) == [], "T4a: partial should not emit yet"
    leftover = on_flush(state, DIR)
    assert len(leftover) == 1 and leftover[0] == frame_a[:5], f"T4b flush mismatch"

    # Test 5: shared state between directions (cross-direction correlation)
    shared: dict = {}
    on_data(frame_a, shared, "c2s")
    shared["last_seen"] = "query"          # c2s sets a marker
    on_data(frame_b, shared, "s2c")
    assert shared.get("last_seen") == "query", "T5: shared state not visible cross-direction"

    print("All tests passed.", file=sys.stderr)
