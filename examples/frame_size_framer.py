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

The framer reads bytes 3–4 (0-indexed) of every incoming frame, interprets
them as a big-endian unsigned 16-bit integer, and buffers data until exactly
that many bytes have arrived — then emits one complete Frame.

Usage in ProtoPoke
------------------
In the Config tab, click **Edit** next to *Framer*, choose *custom*, then set:

  Script path : /path/to/this/file/frame_size_framer.py
  Class name  : FrameSizeFramer

The framer takes no extra kwargs.

Example wire bytes
------------------
If the first five bytes of an incoming message are:

    0x01  0x00  0x00  0x00  0x14

Then bytes[3:5] = 0x00 0x14  →  total_length = 20.
The framer will buffer 20 bytes before emitting a Frame.
"""

from __future__ import annotations

import struct

from protopoke.framing.base import Framer
from protopoke.models import Frame


class FrameSizeFramer(Framer):
    """
    Custom framer that derives the total frame size from bytes 3–4 of the frame.

    Bytes at offset 3 and 4 (0-indexed) are interpreted as a big-endian
    unsigned 16-bit integer (*total* frame length, inclusive of the header).

    Args:
        session_id:     Session this framer belongs to.
        direction:      Direction of the stream.
        max_frame_size: Safety cap (default 64 KiB).  If the declared length
                        exceeds this value the buffer is flushed immediately
                        to prevent unbounded memory growth.
    """

    # Minimum bytes we must have before we can read the length field.
    _HEADER_SIZE: int = 5  # bytes 0-4 must be present

    # Offset and format of the length field within the header.
    _LENGTH_OFFSET: int = 3
    _LENGTH_FORMAT: str = ">H"  # big-endian unsigned 16-bit int

    def __init__(
        self,
        session_id: str,
        direction,
        max_frame_size: int = 64 * 1024,
    ) -> None:
        super().__init__(session_id, direction)
        self._buffer: bytearray = bytearray()
        self._max_frame_size: int = max_frame_size

    @property
    def name(self) -> str:
        return "frame_size"

    # ------------------------------------------------------------------
    # Framer interface
    # ------------------------------------------------------------------

    def feed(self, data: bytes) -> list[Frame]:
        """
        Accumulate *data* and emit complete frames.

        Returns a list of zero or more :class:`~protopoke.models.Frame`
        objects.  Returns an empty list if more bytes are needed.
        """
        self._buffer.extend(data)
        frames: list[Frame] = []

        while True:
            # Need the full header before we can read the length field.
            if len(self._buffer) < self._HEADER_SIZE:
                break

            # Bytes 3 and 4 → big-endian uint16 = total frame length.
            (total_length,) = struct.unpack_from(
                self._LENGTH_FORMAT, self._buffer, self._LENGTH_OFFSET
            )

            if total_length > self._max_frame_size:
                # Safety: corrupt data or misconfigured framer — emit and reset.
                frames.append(self._make_frame(bytes(self._buffer)))
                self._buffer.clear()
                break

            if total_length < self._HEADER_SIZE:
                # Declared length smaller than header — treat as corrupt, emit.
                frames.append(self._make_frame(bytes(self._buffer)))
                self._buffer.clear()
                break

            if len(self._buffer) < total_length:
                # Frame not yet complete — wait for more data.
                break

            # We have a complete frame.
            frame_bytes = bytes(self._buffer[:total_length])
            frames.append(self._make_frame(frame_bytes))
            del self._buffer[:total_length]

        return frames

    def flush(self) -> list[Frame]:
        """Emit any remaining buffered bytes as a partial final frame."""
        if self._buffer:
            frame = self._make_frame(bytes(self._buffer))
            self._buffer.clear()
            return [frame]
        return []

    def reset(self) -> None:
        """Clear buffer and reset sequence counter."""
        self._buffer.clear()
        self._sequence = 0


# ---------------------------------------------------------------------------
# Quick smoke-test (run this file directly: python frame_size_framer.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    # Minimal stubs so the test runs without a full ProtoPoke install.
    try:
        from protopoke.models import Direction
    except ImportError:
        from enum import Enum

        class Direction(Enum):  # type: ignore[no-redef]
            CLIENT_TO_SERVER = "c2s"
            SERVER_TO_CLIENT = "s2c"

    framer = FrameSizeFramer(session_id="test", direction=Direction.CLIENT_TO_SERVER)

    # Build a 20-byte frame: header (5 bytes) + 15-byte payload.
    # Bytes 3-4 carry the total length: 0x00 0x14 = 20.
    header = bytes([0x01, 0x00, 0x00, 0x00, 0x14])  # total_length = 20
    payload = b"Hello, ProtoPoke!"[:15]              # exactly 15 bytes
    raw = header + payload
    assert len(raw) == 20, f"Expected 20 bytes, got {len(raw)}"

    # Feed in two chunks to exercise buffering.
    frames = framer.feed(raw[:10])
    assert frames == [], "Should not have a complete frame yet"
    frames = framer.feed(raw[10:])
    assert len(frames) == 1, f"Expected 1 frame, got {len(frames)}"
    assert frames[0].raw_bytes == raw, "Frame bytes mismatch"

    # Feed two back-to-back frames in one call.
    framer.reset()
    frames = framer.feed(raw + raw)
    assert len(frames) == 2, f"Expected 2 frames, got {len(frames)}"

    print("All tests passed.", file=sys.stderr)
