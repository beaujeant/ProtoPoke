"""
ProxyAPI — the unified control interface.

This is the main entry point for all programmatic control of the proxy.
It wires together all the internal components and exposes a clean facade:

    Session management:
        list_sessions(), get_session(), get_frames()

    Lifecycle:
        start(), stop(), serve_forever()

    Interception:
        intercept_enabled (property, settable)
        get_next_intercepted() — blocks until a frame is intercepted
        list_intercepted() — snapshot of pending queue
        forward(), drop(), modify_and_forward() — verdict shortcuts

    Replay:
        replay_session()

    Events:
        on_session_opened(), on_session_closed(), on_frame_captured()

Why a separate API class:
    - The proxy engine, session registry, intercept controller, event bus,
      and replay engine are all independent components. ProxyAPI composes them.
    - Tests can drive the proxy via ProxyAPI without touching internals.
    - A future HTTP API server (e.g. aiohttp/FastAPI) wraps ProxyAPI methods.
    - A future terminal UI also wraps ProxyAPI — no other layer changes.
    - The intercept controller type (passthrough vs queued) is selected based on
      config here, so callers don't need to think about it.

Usage example:

    config = ProxyConfig(listen_port=8080, upstream_host="10.0.0.1",
                         upstream_port=9090, intercept_enabled=True)
    api = ProxyAPI(config)
    await api.start()

    # In another task:
    while True:
        unit = await api.get_next_intercepted()
        print(unit.frame.raw_bytes)
        api.forward(unit.id)

    await api.stop()
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from .config import ProxyConfig
from .models import Direction, Frame, InterceptedUnit
from .core.proxy import ProxyEngine
from .core.session import Session, SessionRegistry
from .events.bus import (
    EventBus,
    SessionOpenedEvent,
    SessionClosedEvent,
    FrameCapturedEvent,
)
from .intercept.controller import (
    InterceptController,
    PassthroughController,
    QueuedInterceptController,
)
from .replay.engine import ReplayEngine, ReplayResult
from .storage.base import StorageBackend, NullStorageBackend

logger = logging.getLogger(__name__)


class ProxyAPI:
    """
    High-level control interface for the TCP proxy.

    Instantiate with a ProxyConfig, then call start()/stop() or
    serve_forever() to run the proxy.
    """

    def __init__(
        self,
        config:  ProxyConfig,
        storage: Optional[StorageBackend] = None,
    ) -> None:
        self.config = config

        # Shared infrastructure
        self.event_bus        = EventBus()
        self.session_registry = SessionRegistry()
        self.storage          = storage or NullStorageBackend()

        # Select intercept controller based on config
        self._intercept_controller: InterceptController
        if config.intercept_enabled:
            self._intercept_controller = QueuedInterceptController(intercept_enabled=True)
        else:
            self._intercept_controller = PassthroughController()

        # Core engine
        self.engine = ProxyEngine(
            config=config,
            intercept_controller=self._intercept_controller,
            event_bus=self.event_bus,
            session_registry=self.session_registry,
        )

        # Replay engine
        self.replay_engine = ReplayEngine(
            session_registry=self.session_registry,
            connect_timeout=config.connect_timeout,
            framer_name=config.framer_name,
            framer_kwargs=config.framer_kwargs,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start listening for connections (non-blocking)."""
        await self.engine.start()
        logger.info(
            "ProxyAPI started: %s:%d → %s:%d",
            self.config.listen_host, self.config.listen_port,
            self.config.upstream_host, self.config.upstream_port,
        )

    async def serve_forever(self) -> None:
        """Start and block until stop() is called."""
        await self.engine.serve_forever()

    async def stop(self) -> None:
        """Stop the proxy and release all resources."""
        await self.engine.stop()
        await self.storage.close()
        logger.info("ProxyAPI stopped")

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> Optional[Session]:
        """Look up a session by ID. Returns None if not found."""
        return self.session_registry.get(session_id)

    def list_sessions(self) -> list[Session]:
        """All sessions, active and closed."""
        return self.session_registry.all_sessions()

    def list_active_sessions(self) -> list[Session]:
        """Currently active sessions only."""
        return self.session_registry.active_sessions()

    def get_frames(
        self,
        session_id: str,
        direction:  Optional[Direction] = None,
    ) -> list[Frame]:
        """
        Get captured frames for a session.

        Args:
            session_id: The session to query.
            direction:  If given, filter to CLIENT_TO_SERVER or SERVER_TO_CLIENT only.

        Returns:
            List of frames in capture order.
        """
        session = self.session_registry.get(session_id)
        if not session:
            return []

        frames = session.frames
        if direction is not None:
            frames = [f for f in frames if f.direction is direction]
        return frames

    # ------------------------------------------------------------------
    # Interception control
    # ------------------------------------------------------------------

    @property
    def intercept_enabled(self) -> bool:
        """Whether interception is currently active."""
        if isinstance(self._intercept_controller, QueuedInterceptController):
            return self._intercept_controller.intercept_enabled
        return False

    @intercept_enabled.setter
    def intercept_enabled(self, value: bool) -> None:
        """
        Enable or disable interception at runtime.

        When disabled, all currently pending frames are immediately forwarded.
        When enabled, subsequent frames are held for operator review.

        Note: if the proxy was started without intercept_enabled=True in config,
        the intercept controller is a PassthroughController and toggling this
        property has no effect (logs a warning).
        """
        if isinstance(self._intercept_controller, QueuedInterceptController):
            self._intercept_controller.intercept_enabled = value
        elif value:
            logger.warning(
                "Cannot enable interception: proxy was started with intercept_enabled=False. "
                "Set intercept_enabled=True in ProxyConfig and restart."
            )

    async def get_next_intercepted(self) -> InterceptedUnit:
        """
        Wait for and return the next intercepted frame.

        Blocks until a frame arrives in the intercept queue.

        Raises:
            RuntimeError: if interception is not enabled.
        """
        if not isinstance(self._intercept_controller, QueuedInterceptController):
            raise RuntimeError(
                "Interception not enabled. "
                "Create ProxyAPI with ProxyConfig(intercept_enabled=True)."
            )
        return await self._intercept_controller.get_pending()

    def list_intercepted(self) -> list[InterceptedUnit]:
        """Snapshot of all frames currently waiting for a verdict."""
        if not isinstance(self._intercept_controller, QueuedInterceptController):
            return []
        return self._intercept_controller.list_pending()

    def pending_count(self) -> int:
        """Number of frames waiting for an intercept verdict."""
        if not isinstance(self._intercept_controller, QueuedInterceptController):
            return 0
        return self._intercept_controller.pending_count()

    def forward(self, unit_id: str) -> bool:
        """Forward an intercepted frame as-is."""
        if not isinstance(self._intercept_controller, QueuedInterceptController):
            return False
        return self._intercept_controller.forward(unit_id)

    def drop(self, unit_id: str) -> bool:
        """Drop an intercepted frame (don't forward it)."""
        if not isinstance(self._intercept_controller, QueuedInterceptController):
            return False
        return self._intercept_controller.drop(unit_id)

    def modify_and_forward(self, unit_id: str, new_data: bytes) -> bool:
        """Forward an intercepted frame with replacement bytes."""
        if not isinstance(self._intercept_controller, QueuedInterceptController):
            return False
        return self._intercept_controller.modify_and_forward(unit_id, new_data)

    def forward_all(self) -> int:
        """Forward all currently pending intercepted frames. Returns count."""
        if not isinstance(self._intercept_controller, QueuedInterceptController):
            return 0
        return self._intercept_controller.forward_all()

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    async def replay_session(
        self,
        session_id:      str,
        server_host:     Optional[str]              = None,
        server_port:     Optional[int]              = None,
        frame_delay:     float                      = 0.0,
        modified_frames: Optional[dict[str, bytes]] = None,
    ) -> ReplayResult:
        """
        Replay a captured session.

        Args:
            session_id:      Session to replay. Must exist in the registry.
            server_host:     Override target host (default: original server).
            server_port:     Override target port (default: original server).
            frame_delay:     Seconds to wait between sending each frame.
            modified_frames: Dict of frame_id → replacement bytes.
                             Frames not in the dict use original bytes.

        Returns:
            ReplayResult with the new replayed session and result metadata.
        """
        return await self.replay_engine.replay_session(
            session_id=session_id,
            server_host=server_host,
            server_port=server_port,
            frame_delay=frame_delay,
            modified_frames=modified_frames,
        )

    # ------------------------------------------------------------------
    # Event subscriptions
    # ------------------------------------------------------------------

    def on_session_opened(self, handler: Callable) -> None:
        """Register a handler for SessionOpenedEvent."""
        self.event_bus.subscribe(SessionOpenedEvent, handler)

    def on_session_closed(self, handler: Callable) -> None:
        """Register a handler for SessionClosedEvent."""
        self.event_bus.subscribe(SessionClosedEvent, handler)

    def on_frame_captured(self, handler: Callable) -> None:
        """
        Register a handler for FrameCapturedEvent.

        The handler receives a FrameCapturedEvent with .frame and .session.

        Example:
            async def my_handler(event: FrameCapturedEvent):
                print(f"Frame from {event.session.id[:8]}: {event.frame.raw_bytes!r}")

            api.on_frame_captured(my_handler)
        """
        self.event_bus.subscribe(FrameCapturedEvent, handler)
