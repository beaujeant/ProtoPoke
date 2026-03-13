"""
Delimiter-based framer.

Splits the byte stream whenever a fixed byte sequence is found.
Useful for line-based and request/response protocols.

Examples:
    Line-based protocols (syslog, SMTP commands, Redis inline):
        DelimiterFramer(..., delimiter=b'\\n')

    HTTP-style header blocks:
        DelimiterFramer(..., delimiter=b'\\r\\n\\r\\n')

    Null-terminated strings:
        DelimiterFramer(..., delimiter=b'\\x00')

Safety:
    If the buffer grows past max_frame_size without a delimiter, it is emitted
    as one oversized frame and the buffer is cleared. This prevents unbounded
    memory growth on protocols that never produce the expected delimiter
    (e.g. wrong framer configuration, binary protocol, connection issues).
"""

from __future__ import annotations

from ..models import Direction, Frame
from .base import Framer


class DelimiterFramer(Framer):
    """
    Splits the byte stream on a fixed byte sequence.

    Args:
        session_id:     Session this framer belongs to.
        direction:      Direction of the stream.
        delimiter:      Byte sequence to split on. Default: newline (b'\\n').
        max_frame_size: Safety limit: emit and clear the buffer if it grows
                        this large without finding a delimiter. Default: 1 MB.
    """

    def __init__(
        self,
        session_id:     str,
        direction:      Direction,
        delimiter:      bytes = b'\n',
        max_frame_size: int   = 1024 * 1024,
    ) -> None:
        super().__init__(session_id, direction)
        if not delimiter:
            raise ValueError("delimiter must be a non-empty byte sequence")
        self._delimiter      = delimiter
        self._max_frame_size = max_frame_size
        self._buffer         = bytearray()

    @property
    def name(self) -> str:
        return "delimiter"

    def feed(self, data: bytes) -> list[Frame]:
        """
        Accumulate bytes and emit frames whenever the delimiter is found.

        May emit zero frames (delimiter not yet seen) or multiple frames
        (multiple delimiters found in one read).
        """
        self._buffer.extend(data)
        frames: list[Frame] = []

        while True:
            idx = self._buffer.find(self._delimiter)
            if idx == -1:
                break  # No complete frame yet

            end = idx + len(self._delimiter)
            frame_bytes = bytes(self._buffer[:end])

            frames.append(self._make_frame(frame_bytes))
            del self._buffer[:end]

        # Safety: if buffer is too large, emit it as-is and reset
        if len(self._buffer) > self._max_frame_size:
            frames.append(self._make_frame(bytes(self._buffer)))
            self._buffer.clear()

        return frames

    def flush(self) -> list[Frame]:
        """Emit any remaining buffered bytes as a final (incomplete) frame."""
        if self._buffer:
            frame = self._make_frame(bytes(self._buffer))
            self._buffer.clear()
            return [frame]
        return []

    def reset(self) -> None:
        """Clear buffer and reset sequence counter."""
        self._buffer.clear()
        self._sequence = 0
