"""
Length-prefix framer.

Handles the common pattern where each message is preceded by a fixed-size
integer that encodes the length of the following payload.

    [N-byte big-endian uint][payload bytes of that length]

This pattern appears in many binary protocols: custom game protocols,
database wire formats, message queue protocols, etc.

Configuration:
    prefix_length: 1, 2, 4, or 8 bytes (default: 4)
    byte_order:    'big' or 'little' endian (default: 'big')
    include_prefix: Whether the emitted Frame includes the prefix bytes.
                    True  → frame.raw_bytes = prefix + payload (default)
                    False → frame.raw_bytes = payload only

Safety:
    If the declared payload length exceeds max_frame_size, the framer emits
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

    Reads a fixed-size integer header, then collects exactly that many
    payload bytes before emitting a Frame.
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
        include_prefix: bool  = True,
        max_frame_size: int   = 16 * 1024 * 1024,  # 16 MB
    ) -> None:
        super().__init__(session_id, direction)

        key = (prefix_length, byte_order)
        if key not in self._FORMATS:
            raise ValueError(
                f"Unsupported (prefix_length, byte_order): {key}. "
                f"Supported: {list(self._FORMATS.keys())}"
            )

        self._prefix_length  = prefix_length
        self._struct         = struct.Struct(self._FORMATS[key])
        self._include_prefix = include_prefix
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

        while len(self._buffer) >= self._prefix_length:
            # Parse the length header
            (payload_length,) = self._struct.unpack_from(self._buffer, 0)
            total_length = self._prefix_length + payload_length

            if payload_length > self._max_frame_size:
                # Corrupt data or wrong framer config — emit and reset
                frames.append(self._make_frame(bytes(self._buffer)))
                self._buffer.clear()
                break

            if len(self._buffer) < total_length:
                # We have the header but not the full payload yet
                break

            if self._include_prefix:
                frame_bytes = bytes(self._buffer[:total_length])
            else:
                frame_bytes = bytes(self._buffer[self._prefix_length:total_length])

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
