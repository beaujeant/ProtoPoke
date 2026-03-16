"""
SequenceEngine — runs a sequence of packets with variable substitution.

The engine is deliberately decoupled from ProxyAPI: it receives the network
I/O as a single async callable (``send_fn``) so that the caller (ProxyAPI or
tests) can wire in any transport without introducing import cycles.
"""

from __future__ import annotations

import logging
from typing import Awaitable, Callable, Dict, List, Optional

from .models import HistoryEntry, SequenceSession
from .variables import resolve_hex

logger = logging.getLogger(__name__)

# Type alias for the send callable supplied by the caller.
# Receives the bytes to send and the frame direction ("client_to_server" or
# "server_to_client"), returns the list of received packets (may be empty).
SendFn = Callable[[bytes, str], Awaitable[List[bytes]]]


class SequenceEngine:
    """
    Runs a :class:`~protopoke.sequence.models.SequenceSession`.

    Usage::

        engine = SequenceEngine()

        async def send_fn(data: bytes) -> list[bytes]:
            # open connection, send data, collect + return response packets
            ...

        await engine.run(seq, send_fn=send_fn)
    """

    async def run(
        self,
        seq:              SequenceSession,
        send_fn:          SendFn,
        on_entry:         Optional[Callable[[HistoryEntry], None]] = None,
        global_variables: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Execute all frames in *seq* in order.

        For each frame:
          1. Resolve ``{{VAR}}`` placeholders against the current variable store.
          2. Record a ``HistoryEntry`` (direction=sent).
          3. Call ``send_fn(data)`` and collect received packets.
          4. Record a ``HistoryEntry`` per received packet (direction=received).

        Args:
            seq:              The sequence to run.  ``seq.history`` and
                              ``seq.variables`` are updated in-place.
            send_fn:          Async callable that sends bytes and returns the
                              list of received packet chunks.
            on_entry:         Optional callback invoked immediately after each
                              :class:`HistoryEntry` is created.  Useful for
                              live UI updates without polling.
            global_variables: Optional global variable store shared across all
                              pipelines.  Used as a fallback for ``{{VAR}}``
                              placeholder resolution: sequence-local variables
                              take priority; global variables fill in the rest.
                              This allows a traffic script (e.g. on intercept)
                              to capture a value and have the sequence use it
                              via ``{{VAR}}`` without any extra plumbing.
        """
        # Sequence-local variables take priority over global ones.
        variables: Dict[str, str] = dict(seq.variables)
        _global = global_variables if global_variables is not None else {}

        def _effective_vars() -> Dict[str, str]:
            """Merge global (base) + local (override) for placeholder resolution."""
            return {**_global, **variables}

        def _emit(entry: HistoryEntry) -> None:
            seq.history.append(entry)
            if on_entry is not None:
                on_entry(entry)

        for frame_idx, frame in enumerate(seq.frames):
            # ------------------------------------------------------------------
            # 1. Resolve {{VAR}} placeholders
            # ------------------------------------------------------------------
            try:
                data = resolve_hex(frame.raw_hex, _effective_vars())
            except ValueError as exc:
                logger.error(
                    "Sequence frame %d (%r): placeholder resolution failed — %s",
                    frame_idx, frame.label, exc,
                )
                continue

            # ------------------------------------------------------------------
            # 2. Record sent packet
            # ------------------------------------------------------------------
            _emit(HistoryEntry.create_sent(data, frame.label))

            # ------------------------------------------------------------------
            # 3. Send and collect response
            # ------------------------------------------------------------------
            received_packets: list[bytes] = []
            try:
                received_packets = await send_fn(data, frame.direction)
            except Exception as exc:
                logger.error(
                    "Sequence frame %d (%r): send_fn raised — %s", frame_idx, frame.label, exc
                )

            # ------------------------------------------------------------------
            # 4. Record received packets
            # ------------------------------------------------------------------
            for pkt in received_packets:
                _emit(HistoryEntry.create_received(pkt, frame.label))

        # Persist updated variable state back into the session
        seq.variables = variables
