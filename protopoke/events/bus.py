"""
Event bus — pub/sub observer for proxy lifecycle events.

Any component can publish events; any component can subscribe to them.
This keeps layers decoupled: the relay doesn't need to know about the UI;
the UI doesn't need to know about the relay.

Design:
    - Handlers are async coroutines (fits naturally into asyncio)
    - asyncio.gather() runs all handlers for an event concurrently
    - Handler exceptions are caught and logged; they never kill the publisher
    - No queues, no guaranteed delivery — this is for observation, not commands
      (the intercept controller handles the command path separately)

The UI layer subscribes to FrameCapturedEvent / SessionOpenedEvent / etc.
to update its display.  It goes through ProtoPokeAPI rather than touching
the relay or the intercept controller directly.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Awaitable

from ..models import Frame, SessionInfo, TamperedUnit

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

@dataclass
class SessionOpenedEvent:
    """Emitted when a client has connected and the upstream connection is up."""
    session: SessionInfo


@dataclass
class SessionClosedEvent:
    """Emitted when both sides of a session have fully closed."""
    session: SessionInfo


@dataclass
class SessionUpdatedEvent:
    """Emitted when a session state changes mid-session (one side disconnects)."""
    session: SessionInfo


@dataclass
class FrameCapturedEvent:
    """Emitted for every frame captured by the relay (before interception)."""
    frame:   Frame
    session: SessionInfo


@dataclass
class InterceptCompletedEvent:
    """Emitted when a verdict is set and the frame leaves the intercept queue."""
    unit:    TamperedUnit
    session: SessionInfo


@dataclass
class UpstreamConnectionFailedEvent:
    """Emitted when a client connected but the proxy could not reach upstream."""
    forwarder_name: str
    client_host:    str
    client_port:    int
    upstream_host:  str
    upstream_port:  int
    error:          str


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------

# Type alias for async event handlers
AsyncHandler = Callable[..., Awaitable[None]]


class EventBus:
    """
    Simple async publish/subscribe event bus.

    Usage:
        bus = EventBus()

        async def on_frame(event: FrameCapturedEvent):
            print(f"Frame: {event.frame.id}")

        bus.subscribe(FrameCapturedEvent, on_frame)
        await bus.publish(FrameCapturedEvent(frame=..., session=...))

    Thread safety:
        Not thread-safe. Intended for use within a single asyncio event loop.
        If you need cross-thread event delivery, put asyncio.Queue in between.
    """

    def __init__(self) -> None:
        # Map event_type -> list of registered handlers
        self._handlers: dict[type, list[AsyncHandler]] = {}

    def subscribe(self, event_type: type, handler: AsyncHandler) -> None:
        """Register an async handler for a specific event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: type, handler: AsyncHandler) -> None:
        """Unregister a previously registered handler."""
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def publish(self, event: object) -> None:
        """
        Publish an event to all registered handlers.

        All handlers run concurrently via asyncio.gather(). Exceptions
        are logged and swallowed — a broken observer never breaks the proxy.
        """
        event_type = type(event)
        handlers = self._handlers.get(event_type, [])

        if not handlers:
            return

        results = await asyncio.gather(
            *(handler(event) for handler in handlers),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception):
                logger.error(
                    "Event handler exception for %s: %s",
                    event_type.__name__,
                    result,
                    exc_info=result,
                )
