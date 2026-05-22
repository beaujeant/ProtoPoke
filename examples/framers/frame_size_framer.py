"""
Example custom framer: byte-range length field.

Frame layout expected by this framer
-------------------------------------
Offset  Size  Description
------  ----  -----------
0       1     Message type  (arbitrary)
1       1     Flags         (arbitrary)
2       1     Reserved      (arbitrary)
3       2     Total length  ← big-endian uint16, counts ALL bytes including header
5+      N     Payload

Usage in ProtoPoke
------------------
Config tab → Edit Framer → Custom, then set:

  Script path : /path/to/examples/framers/frame_size_framer.py

That is all.

How a custom framer works
--------------------------
A custom framer is two plain functions — no class, no imports from ProtoPoke:

    def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
        ...

    def on_flush(state: dict, direction: str) -> list[bytes]:
        ...

``state`` is a plain dict shared between BOTH directions for the lifetime
of the session.  Use ``direction`` ("c2s" or "s2c") as a key to keep
per-direction buffers separate:

    buf = state.setdefault(direction, bytearray())

Cross-direction correlation is free — anything written under a plain key in
one direction call is visible in the next call for the other direction.
"""

from __future__ import annotations

import struct

_HEADER_SIZE   = 5       # must have at least 5 bytes before reading the length field
_LENGTH_OFFSET = 3       # byte offset of the uint16 total-length field
_MAX_FRAME     = 64 * 1024


def on_data(data: bytes, state: dict, direction: str) -> list[bytes]:
    """
    Accumulate *data* and return complete frames.

    Reads the big-endian uint16 at bytes 3–4 of the frame header to
    determine total frame length (header + payload), then buffers until
    that many bytes have arrived.
    """
    buf = state.setdefault(direction, bytearray())
    buf.extend(data)
    frames: list[bytes] = []

    while True:
        if len(buf) < _HEADER_SIZE:
            break

        (total_length,) = struct.unpack_from(">H", buf, _LENGTH_OFFSET)

        if total_length > _MAX_FRAME or total_length < _HEADER_SIZE:
            # Corrupt / implausible length — emit everything and restart.
            frames.append(bytes(buf))
            buf.clear()
            break

        if len(buf) < total_length:
            break  # incomplete frame — wait for more data

        frames.append(bytes(buf[:total_length]))
        del buf[:total_length]

    return frames


def on_flush(state: dict, direction: str) -> list[bytes]:
    """Emit any remaining buffered bytes when the connection closes."""
    buf = state.pop(direction, bytearray())
    return [bytes(buf)] if buf else []


# ---------------------------------------------------------------------------
# Quick smoke-test (run this file directly: python frame_size_framer.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    DIR = "c2s"
    state: dict = {}

    # Build a 20-byte frame: header (5 bytes) + 15-byte payload.
    # Bytes 3-4 carry the total length: 0x00 0x14 = 20.
    header = bytes([0x01, 0x00, 0x00, 0x00, 0x14])  # total_length = 20
    payload = b"Hello, ProtoPoke!"[:15]
    raw = header + payload
    assert len(raw) == 20

    # Feed in two chunks to exercise buffering.
    assert on_data(raw[:10], state, DIR) == [], "T1a: should buffer partial frame"
    result = on_data(raw[10:], state, DIR)
    assert len(result) == 1 and result[0] == raw, f"T1b failed: {result}"

    # Two back-to-back frames in one call.
    state.pop(DIR, None)
    result = on_data(raw + raw, state, DIR)
    assert len(result) == 2, f"T2 failed: {result}"

    # Shared state between directions.
    shared: dict = {}
    on_data(raw, shared, "c2s")
    shared["seq"] = 1
    on_data(raw, shared, "s2c")
    assert shared.get("seq") == 1, "T3: shared state not visible cross-direction"

    print("All tests passed.", file=sys.stderr)
