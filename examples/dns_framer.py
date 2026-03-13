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

This framing is used by:
  - DNS over TCP (port 53, RFC 1035)
  - DNS over TLS — DoT (port 853, RFC 7858)
  - DNS over QUIC stream framing (RFC 9250) — same prefix convention

Desync recovery
---------------
DNS over TCP has no magic bytes or sync markers.  If the framer encounters
a declared length that looks wrong (too small for a valid DNS header, or
larger than the configured safety cap) it calls on_desync().

Because there are no reliable sync markers the default on_desync()
implementation flushes the entire buffer: the bad bytes are emitted as a
single raw frame (so nothing is silently lost), and framing restarts cleanly
from the next data that arrives on the socket.

If your deployment uses a fixed-prefix wrapper around DNS (e.g. an in-house
multiplexing layer that starts every datagram with 0xAB 0xCD), override
on_desync() and search for that marker:

    def on_desync(self, buffer: bytearray) -> int:
        SYNC = b'\\xAB\\xCD'
        idx = buffer.find(SYNC, 1)          # start at 1 to skip current bad pos
        return idx if idx != -1 else len(buffer)

Usage in ProtoPoke
------------------
Config tab → Edit Framer → Custom, then set:

  Script path : /path/to/examples/dns_framer.py
  Class name  : DnsFramer

The framer accepts one optional kwarg:

  max_frame_size (int, default 65 535): hard cap on declared message length.
      Any declared length above this value triggers desync recovery instead
      of waiting for an absurdly large payload.
"""

from __future__ import annotations

import struct

from protopoke.framing.base import Framer
from protopoke.models import Frame

# Every DNS message must carry at least the 12-byte fixed header:
#   2 B  Transaction ID
#   2 B  Flags
#   2 B  QDCOUNT  (number of questions)
#   2 B  ANCOUNT  (number of answers)
#   2 B  NSCOUNT  (number of authority records)
#   2 B  ARCOUNT  (number of additional records)
_DNS_MIN_MSG = 12

# The TCP length prefix is always exactly 2 bytes.
_PREFIX_LEN = 2


class DnsFramer(Framer):
    """
    Framer for DNS over TCP (RFC 1035 §4.2.2).

    Reads the 2-byte big-endian length prefix that precedes each DNS message
    and buffers data until the full message has arrived, then emits one Frame
    containing both the prefix and the DNS message bytes.

    Args:
        session_id:     Session this framer belongs to.
        direction:      Direction of the stream.
        max_frame_size: Hard cap on the declared DNS message length in bytes.
                        Defaults to 65 535 (the maximum a uint16 can express).
                        Any declared length above this value is treated as a
                        framing error and triggers on_desync() recovery.
    """

    def __init__(
        self,
        session_id: str,
        direction,
        max_frame_size: int = 0xFFFF,
    ) -> None:
        super().__init__(session_id, direction)
        self._buffer: bytearray = bytearray()
        self._max_frame_size: int = max_frame_size

    @property
    def name(self) -> str:
        return "dns"

    # ------------------------------------------------------------------
    # Framer interface
    # ------------------------------------------------------------------

    def feed(self, data: bytes) -> list[Frame]:
        """
        Accumulate *data* and emit complete DNS-over-TCP frames.

        Each emitted Frame contains the 2-byte length prefix followed by the
        DNS message — exactly the bytes that appeared on the wire.

        Returns a list of zero or more Frames.  Returns an empty list if more
        data is needed to complete the current message.
        """
        self._buffer.extend(data)
        frames: list[Frame] = []

        while len(self._buffer) >= _PREFIX_LEN:
            # Peek at the declared message length.
            (msg_len,) = struct.unpack_from(">H", self._buffer, 0)

            # Validate before committing to read msg_len bytes.
            if msg_len < _DNS_MIN_MSG or msg_len > self._max_frame_size:
                # Declared length is implausible — we are desynced.
                # Delegate to on_desync() to decide how many bytes to skip.
                skip = self.on_desync(self._buffer)
                if skip <= 0:
                    break  # on_desync wants more data before deciding
                skip = min(skip, len(self._buffer))
                frames.append(self._make_frame(bytes(self._buffer[:skip])))
                del self._buffer[:skip]
                continue  # retry parsing from the new buffer position

            # Total on-wire size: prefix + message.
            total = _PREFIX_LEN + msg_len
            if len(self._buffer) < total:
                break  # incomplete message — wait for more data

            # We have a complete frame: emit prefix + message together.
            frames.append(self._make_frame(bytes(self._buffer[:total])))
            del self._buffer[:total]

        return frames

    def flush(self) -> list[Frame]:
        """
        Emit any remaining buffered bytes as a partial final frame.

        Called when the connection closes.  If a DNS message arrived
        incomplete (e.g. the sender crashed mid-transmission), whatever
        bytes were buffered are still captured and visible in the session log.
        """
        if self._buffer:
            frame = self._make_frame(bytes(self._buffer))
            self._buffer.clear()
            return [frame]
        return []

    def reset(self) -> None:
        """Clear buffer and reset sequence counter."""
        self._buffer.clear()
        self._sequence = 0

    # ------------------------------------------------------------------
    # Desync recovery
    # ------------------------------------------------------------------

    def on_desync(self, buffer: bytearray) -> int:
        """
        Determine how many bytes to skip after detecting a framing error.

        DNS over TCP carries no magic bytes or per-frame sync markers, so
        forward-scanning cannot reliably distinguish a true frame boundary
        from a coincidental byte pattern.  The safest strategy is therefore
        to flush the entire buffer: all queued bytes are emitted as one raw
        frame (nothing is silently discarded), and framing restarts cleanly
        the next time data arrives.

        If your deployment wraps DNS inside a custom transport layer that
        DOES have sync markers, override this method and search for them::

            def on_desync(self, buffer: bytearray) -> int:
                SYNC = b'\\xAB\\xCD'
                idx = buffer.find(SYNC, 1)   # skip offset 0 (already bad)
                return idx if idx != -1 else len(buffer)

        Returns:
            ``len(buffer)`` — flush everything and restart.
        """
        return len(buffer)


# ---------------------------------------------------------------------------
# Smoke-test (run directly: python dns_framer.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    try:
        from protopoke.models import Direction
    except ImportError:
        from enum import Enum

        class Direction(Enum):  # type: ignore[no-redef]
            CLIENT_TO_SERVER = "c2s"
            SERVER_TO_CLIENT = "s2c"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _wrap(dns_msg: bytes) -> bytes:
        """Prepend the 2-byte TCP length prefix to a DNS message."""
        return struct.pack(">H", len(dns_msg)) + dns_msg

    # Minimal 12-byte DNS query header (no question/answer records):
    #   ID=0x1234, Flags=0x0100 (RD=1), QDCOUNT=1, rest=0.
    _QUERY_HEADER = bytes([
        0x12, 0x34,  # Transaction ID
        0x01, 0x00,  # Flags: recursion desired
        0x00, 0x01,  # QDCOUNT = 1
        0x00, 0x00,  # ANCOUNT = 0
        0x00, 0x00,  # NSCOUNT = 0
        0x00, 0x00,  # ARCOUNT = 0
    ])

    # A slightly longer query that includes a question for example.com A.
    _FULL_QUERY = _QUERY_HEADER + (
        b"\x07example\x03com\x00"  # QNAME: example.com
        b"\x00\x01"                # QTYPE:  A
        b"\x00\x01"                # QCLASS: IN
    )

    frame_a = _wrap(_QUERY_HEADER)   # 2 + 12 = 14 bytes
    frame_b = _wrap(_FULL_QUERY)     # 2 + 12 + 17 = 31 bytes

    framer = DnsFramer(session_id="test", direction=Direction.CLIENT_TO_SERVER)

    # ------------------------------------------------------------------
    # Test 1: single frame split across two feeds (simulates TCP segmentation)
    # ------------------------------------------------------------------
    half = len(frame_a) // 2
    result = framer.feed(frame_a[:half])
    assert result == [], f"T1a: expected [], got {result}"
    result = framer.feed(frame_a[half:])
    assert len(result) == 1, f"T1b: expected 1 frame, got {len(result)}"
    assert result[0].raw_bytes == frame_a, "T1c: frame bytes mismatch"

    # ------------------------------------------------------------------
    # Test 2: two back-to-back frames in a single feed (coalesced TCP read)
    # ------------------------------------------------------------------
    framer.reset()
    result = framer.feed(frame_a + frame_b)
    assert len(result) == 2, f"T2: expected 2 frames, got {len(result)}"
    assert result[0].raw_bytes == frame_a
    assert result[1].raw_bytes == frame_b

    # ------------------------------------------------------------------
    # Test 3: desync — declared length is too small to be a valid DNS message
    #
    # Scenario: a length prefix of 3 arrives (3 < DNS minimum of 12).
    # The framer cannot know where this "frame" ends, so on_desync() is
    # triggered.  The bad bytes are emitted as a raw frame so they are
    # still visible in the capture log.  The NEXT feed brings a valid DNS
    # frame, which parses correctly — framing has re-synchronised.
    # ------------------------------------------------------------------
    framer.reset()
    bad = struct.pack(">H", 3)   # length=3, below DNS minimum of 12 → desync
    result = framer.feed(bad)
    assert len(result) == 1, f"T3a: expected 1 desync frame, got {len(result)}"
    assert result[0].raw_bytes == bad, "T3b: desync frame should contain the bad bytes"

    result = framer.feed(frame_a)
    assert len(result) == 1, f"T3c: expected 1 good frame after recovery, got {len(result)}"
    assert result[0].raw_bytes == frame_a, "T3d: recovered frame bytes mismatch"

    # ------------------------------------------------------------------
    # Test 4: flush emits a partial (incomplete) frame on connection close
    # ------------------------------------------------------------------
    framer.reset()
    partial = frame_a[:5]
    assert framer.feed(partial) == [], "T4a: incomplete frame should not be emitted yet"
    leftover = framer.flush()
    assert len(leftover) == 1, f"T4b: expected 1 partial frame from flush, got {len(leftover)}"
    assert leftover[0].raw_bytes == partial, "T4c: flush frame bytes mismatch"

    # ------------------------------------------------------------------
    # Test 5: sequence numbers increment across frames
    # ------------------------------------------------------------------
    framer.reset()
    frames = framer.feed(frame_a + frame_b)
    assert frames[0].sequence_number == 0, "T5a: first frame should have sequence 0"
    assert frames[1].sequence_number == 1, "T5b: second frame should have sequence 1"

    print("All tests passed.", file=sys.stderr)
