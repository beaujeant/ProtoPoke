"""
Length-prefix framer.

Handles the common pattern where each message contains a fixed-size integer
field that encodes the length of the following payload.

General frame layout
--------------------

    [  prefix_offset bytes  ][  prefix_length bytes  ][  payload  ]
    |<------- skipped ------>|<-- length field ------>|<- N bytes->|

where N  =  length_field_value  +  length_add

So the total bytes consumed per frame:

    total = prefix_offset + prefix_length + length_field_value + length_add

Common configurations
---------------------
Simple payload-only length at byte 0 (most common):
    prefix_offset=0, prefix_length=4, length_add=0
    → frame = [4-byte length][payload of that many bytes]

Length field buried inside a fixed header:
    prefix_offset=3, prefix_length=2, length_add=0
    → frame = [3 header bytes][2-byte length][payload]

Length encodes "remaining bytes after this field" with a fixed footer:
    prefix_offset=0, prefix_length=2, length_add=4
    → frame = [2-byte length][payload][4-byte footer]  (footer counted in length_add)

Length encodes the total frame size (self-describing):
    prefix_offset=0, prefix_length=4, length_add=-4
    → length_field = total frame size; subtract prefix to get payload size

Safety
------
    If the computed total_length exceeds max_frame_size, the framer emits
    whatever it has and resets. This catches misconfigured framers or corrupt
    data early.
"""

from __future__ import annotations

import struct

from ..models import Direction, Frame
from .base import Framer


class LengthPrefixFramer(Framer):
    """
    Framer for length-prefix-delimited binary protocols.

    Reads a fixed-size integer field at *prefix_offset* bytes into the
    stream, then collects exactly ``length_field_value + length_add``
    additional bytes before emitting a Frame.

    Args:
        session_id:     Session this framer belongs to.
        direction:      Direction of the stream.
        prefix_length:  Width of the length field in bytes: 1, 2, 4, or 8.
                        Default: 4.
        byte_order:     ``'big'`` or ``'little'`` endian. Default: ``'big'``.
        prefix_offset:  Number of bytes before the length field. These are
                        part of the frame but are skipped when reading the
                        length integer.  Default: 0.
        length_add:     Integer added to the decoded length field value to
                        obtain the actual payload byte count.  Use a positive
                        value when the length encodes fewer bytes than the
                        real payload (e.g. a fixed footer is not counted), or
                        a negative value when the length is self-describing
                        (encodes the total frame size).  Default: 0.
        max_frame_size: Safety cap. Default: 16 MiB.
    """

    # struct format strings for supported (prefix_length, byte_order) combos
    _FORMATS: dict[tuple[int, str], str] = {
        (1, 'big'):    '>B',
        (1, 'little'): '<B',
        (2, 'big'):    '>H',
        (2, 'little'): '<H',
        (4, 'big'):    '>I',
        (4, 'little'): '<I',
        (8, 'big'):    '>Q',
        (8, 'little'): '<Q',
    }

    def __init__(
        self,
        session_id:     str,
        direction:      Direction,
        prefix_length:  int   = 4,
        byte_order:     str   = 'big',
        prefix_offset:  int   = 0,
        length_add:     int   = 0,
        max_frame_size: int   = 16 * 1024 * 1024,  # 16 MB
    ) -> None:
        super().__init__(session_id, direction)

        key = (prefix_length, byte_order)
        if key not in self._FORMATS:
            raise ValueError(
                f"Unsupported (prefix_length, byte_order): {key}. "
                f"Supported: {list(self._FORMATS.keys())}"
            )
        if prefix_offset < 0:
            raise ValueError(f"prefix_offset must be >= 0, got {prefix_offset}")

        self._prefix_offset  = prefix_offset
        self._prefix_length  = prefix_length
        self._struct         = struct.Struct(self._FORMATS[key])
        self._length_add     = length_add
        self._max_frame_size = max_frame_size
        self._buffer         = bytearray()

    @property
    def name(self) -> str:
        return "length_prefix"

    def feed(self, data: bytes) -> list[Frame]:
        """
        Accumulate bytes and emit complete messages.

        Returns zero frames if we don't have a complete message yet.
        Returns multiple frames if more than one complete message arrived.
        """
        self._buffer.extend(data)
        frames: list[Frame] = []

        # Minimum bytes needed before we can even read the length field
        min_header = self._prefix_offset + self._prefix_length

        while len(self._buffer) >= min_header:
            # Decode the length field at its offset
            (length_value,) = self._struct.unpack_from(self._buffer, self._prefix_offset)
            payload_length = length_value + self._length_add
            total_length = min_header + payload_length

            if payload_length < 0 or total_length > self._max_frame_size:
                # Corrupt data or wrong framer config — emit and reset
                frames.append(self._make_frame(bytes(self._buffer)))
                self._buffer.clear()
                break

            if len(self._buffer) < total_length:
                # We have the header but not the full payload yet
                break

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
