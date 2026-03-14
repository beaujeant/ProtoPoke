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

  Script path : /path/to/this/file/frame_size_framer.py

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


class FrameSizeFramer:
    """
    Custom framer that derives the total frame size from bytes 3–4 of the frame.

    Bytes at offset 3 and 4 (0-indexed) are interpreted as a big-endian
    unsigned 16-bit integer (*total* frame length, inclusive of the header).
    """

    _HEADER_SIZE   = 5       # must have at least 5 bytes before reading the length field
    _LENGTH_OFFSET = 3       # byte offset of the uint16 length field
    _MAX_FRAME     = 64 * 1024

    def __init__(self) -> None:
        self._buffer: bytearray = bytearray()

    def on_data(self, data: bytes) -> list[bytes]:
        """
        Accumulate *data* and return complete frames.

        Returns an empty list if more bytes are needed to complete a frame.
        """
        self._buffer.extend(data)
        frames: list[bytes] = []

        while True:
            if len(self._buffer) < self._HEADER_SIZE:
                break

            (total_length,) = struct.unpack_from(">H", self._buffer, self._LENGTH_OFFSET)

            if total_length > self._MAX_FRAME or total_length < self._HEADER_SIZE:
                # Corrupt / implausible length — emit everything and restart.
                frames.append(bytes(self._buffer))
                self._buffer.clear()
                break

            if len(self._buffer) < total_length:
                break  # incomplete frame — wait for more data

            frames.append(bytes(self._buffer[:total_length]))
            del self._buffer[:total_length]

        return frames

    def on_flush(self) -> list[bytes]:
        """Emit any remaining buffered bytes when the connection closes."""
        if self._buffer:
            data = bytes(self._buffer)
            self._buffer.clear()
            return [data]
        return []

    def reset(self) -> None:
        """Clear internal buffer (used by the smoke-test below)."""
        self._buffer.clear()


# ---------------------------------------------------------------------------
# Quick smoke-test (run this file directly: python frame_size_framer.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    framer = FrameSizeFramer()

    # Build a 20-byte frame: header (5 bytes) + 15-byte payload.
    # Bytes 3-4 carry the total length: 0x00 0x14 = 20.
    header = bytes([0x01, 0x00, 0x00, 0x00, 0x14])  # total_length = 20
    payload = b"Hello, ProtoPoke!"[:15]
    raw = header + payload
    assert len(raw) == 20

    # Feed in two chunks to exercise buffering.
    assert framer.on_data(raw[:10]) == []
    result = framer.on_data(raw[10:])
    assert len(result) == 1 and result[0] == raw, f"T1 failed: {result}"

    # Two back-to-back frames in one call.
    framer.reset()
    result = framer.on_data(raw + raw)
    assert len(result) == 2, f"T2 failed: {result}"

    print("All tests passed.", file=sys.stderr)
