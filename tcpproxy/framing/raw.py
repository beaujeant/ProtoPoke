"""
Raw (passthrough) framer.

The simplest possible framer: every chunk of bytes from a single read() call
becomes exactly one Frame. No buffering. No boundary detection.

Use this when:
    - You don't yet know the protocol
    - You want to capture/log traffic with no interpretation overhead
    - You're doing a quick test of the proxy before building a real framer

Limitations (important for replay and interception):
    - Frames don't correspond to protocol messages.
    - A single application message may be split across multiple Frames if
      TCP segments it across multiple read() calls.
    - Multiple application messages may merge into one Frame if they arrive
      in the same read() call.
    - This is acceptable for passthrough capture, but replay of individual
      messages requires a protocol-aware framer.

Replacing this later:
    Set framer_name="delimiter" or "length_prefix" in ProxyConfig, or
    implement a custom Framer subclass and register it in FRAMER_REGISTRY.
"""

from __future__ import annotations

from ..models import Direction, Frame
from .base import Framer


class RawFramer(Framer):
    """Passthrough framer: each read chunk becomes one frame immediately."""

    def __init__(self, session_id: str, direction: Direction) -> None:
        super().__init__(session_id, direction)

    @property
    def name(self) -> str:
        return "raw"

    def feed(self, data: bytes) -> list[Frame]:
        """
        Emit one frame per call, immediately.

        An empty bytes argument (EOF signal from the relay) returns no frames.
        """
        if not data:
            return []
        return [self._make_frame(data)]

    def flush(self) -> list[Frame]:
        """Nothing to flush — the raw framer has no buffer."""
        return []

    def reset(self) -> None:
        """Reset the sequence counter."""
        self._sequence = 0
