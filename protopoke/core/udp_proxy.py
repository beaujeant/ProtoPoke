"""
UDP proxy support.

UDP is connectionless, so the engine fakes "sessions" per
``(client_host, client_port)`` flow:

    - A single listening DatagramTransport binds on ``(listen_host, listen_port)``.
    - The first datagram from a new remote address creates a UdpFlow:
        * a Session record (state ACTIVE — there's no CONNECTING handshake)
        * a per-flow upstream DatagramTransport bound with
          ``remote_addr=(upstream_host, upstream_port)`` so reply datagrams
          route back to ``_UdpUpstreamProtocol``
    - Subsequent datagrams from the same remote address reuse the flow.
    - An idle sweeper closes flows whose ``last_activity`` exceeds
      ``udp_idle_timeout``, transitioning the session ACTIVE → CLOSED.

Per-datagram pipeline mirrors the TCP relay's ``_process_frame`` step:

    raw datagram → RawFramer.feed → 1 Frame
                 → RulesEngine.apply  (replace rules, scope='traffic')
                 → TamperController.process  (may block until operator verdict)
                 → sendto(unit.effective_bytes())

Notes:
    - One datagram = one Frame. The framer is RawFramer for both directions.
    - Tamper is per-datagram. Each datagram is processed in its own asyncio
      Task (spawned from ``datagram_received``), so blocking on tamper does
      NOT block the listening socket — other datagrams continue to arrive.
      A tampered datagram may therefore be reordered relative to subsequent
      un-tampered datagrams; this is intentional and correct for a passive
      interception tool.
    - UDP has no half-close, no ONLY_SERVER / ONLY_CLIENT states, no FIN.
      Sessions transition ACTIVE → CLOSED directly via the idle sweeper or
      explicit ``terminate_session()``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from ..framing.raw import RawFramer
from ..models import Direction, Frame, InterceptAction
from ..events.bus import (
    FrameCapturedEvent,
    InterceptCompletedEvent,
)
from .session import Session

if TYPE_CHECKING:
    from .proxy import ProxyEngine

logger = logging.getLogger(__name__)


@dataclass
class UdpFlow:
    """Per-client-tuple state for a UDP forwarder."""

    session:            Session
    listen_transport:   asyncio.DatagramTransport
    upstream_transport: asyncio.DatagramTransport
    client_addr:        tuple[str, int]
    client_framer:      RawFramer
    server_framer:      RawFramer
    last_activity:      float            = field(default_factory=time.monotonic)
    closed:             bool             = False


class _UdpServerProtocol(asyncio.DatagramProtocol):
    """Listening protocol — one instance per UDP forwarder."""

    def __init__(self, engine: "ProxyEngine") -> None:
        self._engine = engine
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Spawn a task so the receive loop is never blocked by tamper /
        # rules / sendto-drain. Order within a flow is preserved best-effort
        # (asyncio runs created tasks in FIFO from the same callback).
        asyncio.create_task(self._engine._on_udp_client_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        logger.debug("UDP listen error: %s", exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:  # type: ignore[override]
        if exc is not None:
            logger.debug("UDP listen connection_lost: %s", exc)


class _UdpUpstreamProtocol(asyncio.DatagramProtocol):
    """Upstream protocol — one instance per UDP flow."""

    def __init__(self, engine: "ProxyEngine", flow_session_id: str) -> None:
        self._engine = engine
        self._session_id = flow_session_id

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self._engine._on_udp_server_datagram(self._session_id, data))

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        logger.debug(
            "UDP upstream error for session %s: %s",
            self._session_id[:8], exc,
        )

    def connection_lost(self, exc: Optional[Exception]) -> None:  # type: ignore[override]
        if exc is not None:
            logger.debug(
                "UDP upstream connection_lost for session %s: %s",
                self._session_id[:8], exc,
            )


async def process_udp_datagram(
    engine: "ProxyEngine",
    flow: UdpFlow,
    data: bytes,
    direction: Direction,
) -> Optional[bytes]:
    """
    Run a single datagram through the rules + tamper pipeline.

    Returns the bytes that should be forwarded, or ``None`` if the operator
    dropped the frame.

    Updates ``flow.last_activity`` on every call so the idle sweeper sees
    fresh traffic.
    """
    flow.last_activity = time.monotonic()

    framer = flow.client_framer if direction is Direction.CLIENT_TO_SERVER else flow.server_framer
    frames = framer.feed(data)
    if not frames:
        return None
    frame = frames[0]

    flow.session.add_frame(frame)
    await engine.event_bus.publish(
        FrameCapturedEvent(frame=frame, session=flow.session.info)
    )

    effective_frame = frame
    if engine.rules_engine is not None:
        modified_bytes = engine.rules_engine.apply(frame, scope="traffic")
        if modified_bytes != frame.raw_bytes:
            effective_frame = Frame.create(
                session_id=frame.session_id,
                direction=frame.direction,
                raw_bytes=modified_bytes,
                sequence_number=frame.sequence_number,
                framer_name=frame.framer_name,
            )

    unit = await engine.tamper_controller.process(effective_frame)

    await engine.event_bus.publish(
        InterceptCompletedEvent(unit=unit, session=flow.session.info)
    )

    if unit.action is InterceptAction.DROP:
        return None

    out_bytes = unit.effective_bytes()

    if unit.action is InterceptAction.MODIFIED and engine.rules_engine is not None:
        out_bytes = engine.rules_engine.apply_bytes(
            out_bytes, frame.direction, scope="tamper"
        )

    if unit.action is InterceptAction.MODIFIED:
        modified_frame = Frame.create(
            session_id=frame.session_id,
            direction=frame.direction,
            raw_bytes=out_bytes,
            sequence_number=framer.next_sequence(),
            framer_name="tamper",
        )
        flow.session.add_frame(modified_frame)
        await engine.event_bus.publish(
            FrameCapturedEvent(frame=modified_frame, session=flow.session.info)
        )

    return out_bytes
