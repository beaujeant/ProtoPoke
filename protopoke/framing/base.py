"""
Abstract base class for framers.

TCP is a byte stream, not a message stream. Framers are the bridge:
they accumulate raw bytes and emit logical Frame objects when a complete
unit is available.

Why this matters:
    If you intercept raw bytes, your intercept UI shows meaningless chunks
    that don't correspond to application messages. A framer aligned to the
    protocol makes interception and replay meaningful.

Framer contract:
    - Each framer instance is stateful and tied to ONE direction of ONE session.
    - feed() accepts raw bytes from a single read() call and returns zero or
      more complete Frames.
    - flush() is called when the connection closes. It should emit any remaining
      buffered bytes as a final (possibly incomplete) Frame.
    - reset() clears internal state (useful when reusing a framer).
    - The framer is synchronous — async I/O lives at the relay level.

Implementing a custom framer:
    1. Subclass Framer.
    2. Store buffered bytes in self._buffer (bytearray is efficient).
    3. In feed(), scan the buffer for your protocol's message boundaries.
    4. Call self._make_frame(bytes) to create a properly attributed Frame.
    5. In flush(), emit any remaining buffer as a partial frame.

The RawFramer in raw.py is the simplest possible implementation and a
good template to start from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Direction, Frame


class Framer(ABC):
    """
    Abstract base for TCP stream framers.

    Subclass this to implement protocol-aware message boundary detection.
    """

    def __init__(self, session_id: str, direction: Direction) -> None:
        self._session_id = session_id
        self._direction  = direction
        self._sequence   = 0   # monotonically increasing per-direction sequence counter

    @property
    def name(self) -> str:
        """
        Human-readable name for this framer (used in Frame.framer_name).

        Override in subclasses to return a protocol-specific name.
        """
        return self.__class__.__name__.lower()

    # ------------------------------------------------------------------
    # Subclass interface
    # ------------------------------------------------------------------

    @abstractmethod
    def feed(self, data: bytes) -> list[Frame]:
        """
        Feed raw bytes into the framer.

        Args:
            data: Bytes from a single read() call. May be a partial message,
                  a complete message, or multiple messages — the framer handles
                  all cases by buffering internally.

        Returns:
            Zero or more complete Frames. Returns an empty list if more bytes
            are needed before a logical boundary can be found.
        """
        ...

    @abstractmethod
    def flush(self) -> list[Frame]:
        """
        Emit any buffered bytes as a final frame.

        Called when the underlying connection closes. A framer that has
        partially received a message should emit whatever it has so that
        nothing is silently discarded.

        Returns:
            Zero or one Frame containing the remaining buffer bytes.
        """
        ...

    @abstractmethod
    def reset(self) -> None:
        """
        Reset internal state.

        Clears the buffer and resets the sequence counter. Useful when
        reusing a framer instance for a new stream.
        """
        ...

    # ------------------------------------------------------------------
    # Protected helpers for subclasses
    # ------------------------------------------------------------------

    def _next_sequence(self) -> int:
        """Return the next sequence number and increment the counter."""
        seq = self._sequence
        self._sequence += 1
        return seq

    def _make_frame(self, raw_bytes: bytes) -> Frame:
        """
        Create a properly attributed Frame from raw bytes.

        Fills in session_id, direction, sequence_number, and framer_name
        automatically. Subclasses call this instead of constructing Frames
        directly.
        """
        return Frame.create(
            session_id=self._session_id,
            direction=self._direction,
            raw_bytes=raw_bytes,
            sequence_number=self._next_sequence(),
            framer_name=self.name,
        )
