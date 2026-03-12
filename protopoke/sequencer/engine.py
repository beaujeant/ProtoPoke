"""
SequencerEngine — runs a sequence of packets with variable substitution and
optional script hooks.

The engine is deliberately decoupled from ProxyAPI: it receives the network
I/O as a single async callable (``send_fn``) so that the caller (ProxyAPI or
tests) can wire in any transport without introducing import cycles.

Script hooks
------------
The script at ``config.sequencer_script`` (if configured) may define:

    def on_send(data: bytes, variables: dict, step_idx: int, step_label: str) -> bytes:
        '''Called just before each packet is sent (after ##VAR## substitution).
        Return the bytes to actually put on the wire.  If not defined, the
        substituted bytes are sent as-is.'''

    def on_response(response: bytes, variables: dict, step_idx: int, step_label: str) -> None:
        '''Called after the server's response is collected for one step.
        Mutate ``variables`` in-place to capture values for subsequent steps.
        ``response`` is the concatenation of all received packets for this step.'''

Both hooks are optional.  A script that only defines ``on_response`` is the
common case: extract session tokens, increment counters, etc.
"""

from __future__ import annotations

import importlib.util
import logging
import types
from typing import Awaitable, Callable, Dict, List, Optional

from .models import HistoryEntry, SequencerSession
from .variables import resolve_hex

logger = logging.getLogger(__name__)

# Type alias for the send callable supplied by the caller.
# Receives the bytes to send, returns the list of received packets (may be empty).
SendFn = Callable[[bytes], Awaitable[List[bytes]]]


def load_script(path: str) -> types.ModuleType:
    """
    Dynamically load a Python script from *path* and return the module.

    Raises:
        ValueError:      If the file spec cannot be determined.
        FileNotFoundError: If the file does not exist.
        Any exception raised during module execution.
    """
    spec = importlib.util.spec_from_file_location("_sequencer_script", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot create module spec for: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class SequencerEngine:
    """
    Runs a :class:`~protopoke.sequencer.models.SequencerSession`.

    Usage::

        engine = SequencerEngine()

        async def send_fn(data: bytes) -> list[bytes]:
            # open connection, send data, collect + return response packets
            ...

        script = load_script("/path/to/my_protocol.py")
        await engine.run(seq, send_fn=send_fn, script=script)
    """

    async def run(
        self,
        seq:      SequencerSession,
        send_fn:  SendFn,
        script:   Optional[types.ModuleType] = None,
        on_entry: Optional[Callable[[HistoryEntry], None]] = None,
    ) -> None:
        """
        Execute all steps in *seq* in order.

        For each step:
          1. Resolve ``##VAR##`` placeholders against the current variable store.
          2. Call ``script.on_send`` (if defined) for advanced pre-send transforms.
          3. Record a ``HistoryEntry`` (direction=sent).
          4. Call ``send_fn(data)`` and collect received packets.
          5. Record a ``HistoryEntry`` per received packet (direction=received).
          6. Call ``script.on_response`` (if defined) to extract new variable values.

        Variable changes from ``on_response`` are carried forward to all
        subsequent steps.  At the end, ``seq.variables`` is updated in-place
        with the final state.

        Args:
            seq:      The sequence to run.  ``seq.history`` and
                      ``seq.variables`` are updated in-place.
            send_fn:  Async callable that sends bytes and returns the list of
                      received packet chunks.
            script:   Optional loaded module with ``on_send`` / ``on_response``
                      hooks.  Pass ``None`` to skip script execution.
            on_entry: Optional callback invoked immediately after each
                      :class:`HistoryEntry` is created.  Useful for live UI
                      updates without polling.
        """
        variables: Dict[str, str] = dict(seq.variables)

        def _emit(entry: HistoryEntry) -> None:
            seq.history.append(entry)
            if on_entry is not None:
                on_entry(entry)

        for idx, step in enumerate(seq.steps):
            # ------------------------------------------------------------------
            # 1. Resolve ##VAR## placeholders
            # ------------------------------------------------------------------
            try:
                data = resolve_hex(step.raw_hex, variables)
            except ValueError as exc:
                logger.error(
                    "Sequencer step %d (%r): placeholder resolution failed — %s",
                    idx, step.label, exc,
                )
                continue

            # ------------------------------------------------------------------
            # 2. on_send hook
            # ------------------------------------------------------------------
            if script is not None and hasattr(script, "on_send"):
                try:
                    result = script.on_send(data, variables, idx, step.label)
                    if isinstance(result, (bytes, bytearray)):
                        data = bytes(result)
                    else:
                        logger.warning(
                            "on_send at step %d returned %s (expected bytes); ignoring",
                            idx, type(result).__name__,
                        )
                except Exception as exc:
                    logger.error("on_send hook raised at step %d: %s", idx, exc)

            # ------------------------------------------------------------------
            # 3. Record sent packet
            # ------------------------------------------------------------------
            _emit(HistoryEntry.create_sent(data, step.label))

            # ------------------------------------------------------------------
            # 4. Send and collect response
            # ------------------------------------------------------------------
            received_packets: list[bytes] = []
            try:
                received_packets = await send_fn(data)
            except Exception as exc:
                logger.error(
                    "Sequencer step %d (%r): send_fn raised — %s", idx, step.label, exc
                )

            # ------------------------------------------------------------------
            # 5. Record received packets
            # ------------------------------------------------------------------
            for pkt in received_packets:
                _emit(HistoryEntry.create_received(pkt, step.label))

            # ------------------------------------------------------------------
            # 6. on_response hook
            # ------------------------------------------------------------------
            if script is not None and hasattr(script, "on_response"):
                full_response = b"".join(received_packets)
                try:
                    script.on_response(full_response, variables, idx, step.label)
                except Exception as exc:
                    logger.error("on_response hook raised at step %d: %s", idx, exc)

        # Persist updated variable state back into the session
        seq.variables = variables
