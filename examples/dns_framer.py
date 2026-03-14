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

That is all — no class name needed.  ProtoPoke discovers the class
automatically and wraps it.

Writing your own framer
-----------------------
A custom framer is just a plain Python class.  No protopoke imports, no
inheritance.  Implement two methods:

    class MyFramer:
        def on_data(self, data: bytes) -> list[bytes]:
            # called for every raw chunk from the socket
            # return a list of complete message payloads (may be empty)
            ...

        def on_flush(self) -> list[bytes]:
            # called when the connection closes
            # return any partially buffered bytes (or an empty list)
            ...

ProtoPoke handles session attribution, direction, and sequence numbers.
"""

from __future__ import annotations

import struct

# DNS message constants
_DNS_MIN_MSG = 12   # minimum valid DNS payload (fixed 12-byte header)
_PREFIX_LEN  = 2    # TCP length prefix is always 2 bytes


class DnsFramer:
    """
    Framer for DNS over TCP (RFC 1035 §4.2.2).

    Reads the 2-byte big-endian length prefix that precedes each DNS message
    and buffers data until the full message has arrived, then emits one chunk
    containing both the prefix and the DNS message bytes.

    Desync recovery: if the declared length is implausible (< 12 or > 65535)
    the entire buffer is flushed as a raw chunk and framing restarts on the
    next incoming data.
    """

    def __init__(self) -> None:
        self._buffer: bytearray = bytearray()

    def on_data(self, data: bytes) -> list[bytes]:
        """
        Accumulate *data* and return complete DNS-over-TCP message chunks.

        Each returned bytes value contains the 2-byte length prefix followed
        by the DNS message — exactly the bytes that appeared on the wire.
        Returns an empty list if more data is needed.
        """
        self._buffer.extend(data)
        frames: list[bytes] = []

        while len(self._buffer) >= _PREFIX_LEN:
            (msg_len,) = struct.unpack_from(">H", self._buffer, 0)

            if msg_len < _DNS_MIN_MSG or msg_len > 0xFFFF:
                # Implausible length — we are desynced.
                # Emit the whole buffer as a raw chunk and restart.
                frames.append(bytes(self._buffer))
                self._buffer.clear()
                break

            total = _PREFIX_LEN + msg_len
            if len(self._buffer) < total:
                break  # incomplete — wait for more data

            frames.append(bytes(self._buffer[:total]))
            del self._buffer[:total]

        return frames

    def on_flush(self) -> list[bytes]:
        """
        Emit any remaining buffered bytes when the connection closes.

        If a DNS message arrived incomplete (e.g. the sender crashed
        mid-transmission), whatever bytes were buffered are still returned
        so nothing is silently discarded.
        """
        if self._buffer:
            data = bytes(self._buffer)
            self._buffer.clear()
            return [data]
        return []

    def reset(self) -> None:
        """Clear internal buffer (used by the smoke-test below)."""
        self._buffer.clear()


# ---------------------------------------------------------------------------
# Smoke-test (run directly: python dns_framer.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    framer = DnsFramer()

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
    assert framer.on_data(frame_a[:half]) == []
    result = framer.on_data(frame_a[half:])
    assert len(result) == 1 and result[0] == frame_a, f"T1 failed: {result}"

    # Test 2: two back-to-back frames in one feed
    framer.reset()
    result = framer.on_data(frame_a + frame_b)
    assert len(result) == 2 and result[0] == frame_a and result[1] == frame_b, f"T2 failed"

    # Test 3: desync — declared length too small
    framer.reset()
    bad = struct.pack(">H", 3)
    result = framer.on_data(bad)
    assert len(result) == 1 and result[0] == bad, f"T3a failed"
    result = framer.on_data(frame_a)
    assert len(result) == 1 and result[0] == frame_a, f"T3b failed"

    # Test 4: flush emits a partial frame
    framer.reset()
    assert framer.on_data(frame_a[:5]) == []
    leftover = framer.on_flush()
    assert len(leftover) == 1 and leftover[0] == frame_a[:5], f"T4 failed"

    print("All tests passed.", file=sys.stderr)
