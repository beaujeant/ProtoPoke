"""
Example custom framer: DNS over TCP (RFC 1035 §4.2.2).

Wire format
-----------
DNS over TCP wraps every DNS message in a 2-byte big-endian length prefix.
The prefix counts only the DNS message bytes — it does NOT include itself.

    +--------+--------+------ ... ------+
    | LENGTH (2 bytes)|  DNS message    |
    +--------+--------+------ ... ------+
     big-endian uint16   LENGTH bytes

Minimum valid DNS message: 12 bytes (the fixed-size DNS header, no records).
Maximum: 65 535 bytes (the largest value a uint16 can express).

Usage in ProtoPoke
------------------
Config tab → Edit Framer → Custom, then set:

  Script path : /path/to/examples/dns_framer.py

Python API:

  config = ProxyConfig(
      ...,
      custom_framer_path="/path/to/examples/dns_framer.py",
  )

That is all.  ProtoPoke discovers ``on_data`` and ``on_flush`` automatically.

How the custom framer API works
--------------------------------
A custom framer is **two plain module-level functions** — no class, no
imports from ProtoPoke, no subclassing:

    def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
        ...

    def on_flush(state: dict, direction: str) -> list[bytes]:
        ...

Arguments
~~~~~~~~~
data (bytes)
    Raw bytes from the latest ``read()`` call on the TCP socket.  May be
    a partial message, a complete message, or several messages coalesced —
    the framer must handle all three cases by buffering internally.

state (dict)
    A plain mutable dict that ProtoPoke creates **once per proxied
    connection** and passes to every ``on_data`` and ``on_flush`` call for
    **both** directions.  It persists for the entire lifetime of the
    connection and is discarded when the session closes.

    Use ``direction`` as a dict key to keep per-direction accumulation
    buffers separate:

        buf = state.setdefault(direction, bytearray())

    Because the same dict is shared between both directions you can also
    store cross-direction state — data that the client side writes and the
    server side reads (or vice versa):

        # client side
        state["last_query_id"] = transaction_id

        # server side (called later, same state dict)
        qid = state.get("last_query_id")

direction (str)
    ``"c2s"`` when bytes are flowing from the client to the server.
    ``"s2c"`` when bytes are flowing from the server to the client.

Return value of on_data
    ``list[bytes]`` — zero or more complete message payloads ready for
    ProtoPoke to process.  Return ``[]`` if more data is needed before a
    boundary can be found.  Each returned ``bytes`` value becomes one Frame
    in the intercept / log / replay pipeline.

Return value of on_flush
    ``list[bytes]`` — zero or one partial frame containing whatever bytes
    remained in the buffer when the connection closed.  Nothing should be
    silently discarded.

Desync recovery
---------------
DNS over TCP has no magic bytes or per-frame sync markers.  If the framer
encounters a declared length that looks wrong (< 12 bytes, which is smaller
than the mandatory fixed DNS header) it cannot know where the next real
frame starts.

The strategy used here: flush the entire buffer as a single raw frame so
nothing is lost, then restart parsing from the next ``on_data`` call.

If your protocol *does* have a sync marker (e.g. a magic prefix ``0xAB
0xCD`` at the start of every frame), you can recover more precisely by
scanning the buffer for the next occurrence:

    MAGIC = b"\\xab\\xcd"
    idx = buf.find(MAGIC, 1)          # start at 1, skip current bad pos
    skip = idx if idx != -1 else len(buf)
    frames.append(bytes(buf[:skip]))  # emit skipped bytes as raw
    del buf[:skip]
    continue                          # retry from the new position
"""

from __future__ import annotations

import struct

# DNS constants
_DNS_MIN_MSG = 12   # smallest valid DNS payload (fixed 12-byte header)
_PREFIX_LEN  = 2    # TCP length prefix is always exactly 2 bytes


# ---------------------------------------------------------------------------
# Framer functions — these two are discovered automatically by ProtoPoke
# ---------------------------------------------------------------------------

def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    """
    Accumulate *data* in the per-direction buffer and return complete
    DNS-over-TCP message chunks.

    Each returned ``bytes`` value contains the 2-byte length prefix followed
    by the DNS message body — exactly the bytes that appeared on the wire.

    Returns ``[]`` if the buffer does not yet hold a complete message.
    """
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    frames: list[bytes] = []

    while len(buf) >= _PREFIX_LEN:
        (msg_len,) = struct.unpack_from(">H", buf, 0)

        if msg_len < _DNS_MIN_MSG or msg_len > 0xFFFF:
            # Declared length is implausible — the framer is desynced.
            # Emit the whole buffer as a raw chunk so nothing is silently
            # discarded, then restart framing from the next on_data call.
            frames.append(bytes(buf))
            buf.clear()
            break

        total = _PREFIX_LEN + msg_len
        if len(buf) < total:
            break           # incomplete message — wait for more data

        frames.append(bytes(buf[:total]))
        del buf[:total]

    return frames


def on_flush(state: dict, direction: str) -> list[bytes]:
    """
    Emit any remaining buffered bytes when the TCP connection closes.

    If a DNS message arrived incomplete (e.g. the sender crashed
    mid-transmission), whatever bytes were buffered are still returned so
    nothing is silently discarded.
    """
    buf = state.pop(direction, bytearray())
    return [bytes(buf)] if buf else []


# ---------------------------------------------------------------------------
# Smoke-test — run directly: python dns_framer.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    DIR   = "c2s"
    state: dict = {}

    def _wrap(dns_msg: bytes) -> bytes:
        """Prepend the 2-byte TCP length prefix to a DNS payload."""
        return struct.pack(">H", len(dns_msg)) + dns_msg

    # Minimal 12-byte DNS query header (no question/answer records)
    _QUERY_HEADER = bytes([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags: recursion desired
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x00,  # ANCOUNT = 0
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
    ])

    # A slightly longer query: example.com A IN
    _FULL_QUERY = _QUERY_HEADER + b"\x07example\x03com\x00\x00\x01\x00\x01"

    frame_a = _wrap(_QUERY_HEADER)   # 2 + 12 = 14 bytes
    frame_b = _wrap(_FULL_QUERY)     # 2 + 29 = 31 bytes

    # ------------------------------------------------------------------
    # Test 1: frame split across two feeds (simulates TCP segmentation)
    # ------------------------------------------------------------------
    half = len(frame_a) // 2
    assert on_data(frame_a[:half], state, DIR) == [], \
        "T1a: partial frame should not be emitted yet"
    result = on_data(frame_a[half:], state, DIR)
    assert len(result) == 1 and result[0] == frame_a, \
        f"T1b: reassembled frame mismatch — got {result}"

    # ------------------------------------------------------------------
    # Test 2: two frames coalesced in a single read
    # ------------------------------------------------------------------
    state.pop(DIR, None)
    result = on_data(frame_a + frame_b, state, DIR)
    assert len(result) == 2 and result[0] == frame_a and result[1] == frame_b, \
        f"T2: expected 2 frames, got {result}"

    # ------------------------------------------------------------------
    # Test 3: desync — declared length too small to be a valid DNS message
    # ------------------------------------------------------------------
    state.pop(DIR, None)
    bad = struct.pack(">H", 3)   # length=3 < DNS minimum of 12 → desync
    result = on_data(bad, state, DIR)
    assert len(result) == 1 and result[0] == bad, \
        f"T3a: desync frame should contain the bad bytes — got {result}"
    # After desync, framing restarts: the next good frame parses correctly
    result = on_data(frame_a, state, DIR)
    assert len(result) == 1 and result[0] == frame_a, \
        f"T3b: post-desync frame mismatch — got {result}"

    # ------------------------------------------------------------------
    # Test 4: on_flush emits partial bytes on connection close
    # ------------------------------------------------------------------
    state.pop(DIR, None)
    assert on_data(frame_a[:5], state, DIR) == [], \
        "T4a: incomplete frame must not be emitted by on_data"
    leftover = on_flush(state, DIR)
    assert len(leftover) == 1 and leftover[0] == frame_a[:5], \
        f"T4b: on_flush should emit the partial bytes — got {leftover}"

    # ------------------------------------------------------------------
    # Test 5: shared state between directions (cross-direction correlation)
    # ------------------------------------------------------------------
    shared: dict = {}
    on_data(frame_a, shared, "c2s")
    shared["last_query_id"] = 0x1234          # c2s writes a value
    on_data(frame_b, shared, "s2c")
    assert shared.get("last_query_id") == 0x1234, \
        "T5: value written in c2s direction must be visible in s2c direction"

    print("All tests passed.", file=sys.stderr)
