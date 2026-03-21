"""
TCP proxy engine.

The ProxyEngine is the top-level object that:
    1. Binds and listens on a local TCP address.
    2. For each incoming client connection: creates a Session, connects to the
       upstream server, wires up a BidirectionalRelay, and runs it as a Task.
    3. Tracks all active session Tasks so they can be cancelled on shutdown.

This module is intentionally thin. All the interesting behavior lives in:
    - relay.py  (data flow and interception)
    - session.py (session lifecycle)
    - framing/  (byte-stream → frames)
    - tamper/ (tamper queue and verdicts)
    - tls/ (TLS MITM via CertificateAuthority + TLSHandler)

The engine just wires those pieces together for each new connection.

Concurrency model summary:
    - One asyncio server (asyncio.start_server) accepts connections.
    - Each session runs two Tasks (one per relay direction) created inside
      BidirectionalRelay.run(), plus one outer session Task in _run_session().
    - All Tasks share the same event loop — no threads, no locks needed for
      the session registry or intercept queue.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, TYPE_CHECKING

from ..config import ProxyConfig
from ..models import Direction
from ..events.bus import EventBus, SessionOpenedEvent, SessionClosedEvent, SessionUpdatedEvent, UpstreamConnectionFailedEvent
from ..framing import create_framer, load_framer_from_file
from ..tamper.controller import TamperController, PassthroughController
from ..tls.handler import TLSHandler
from .session import SessionRegistry, Session
from .relay import BidirectionalRelay

if TYPE_CHECKING:
    from ..rules.engine import RulesEngine

logger = logging.getLogger(__name__)


class ProxyEngine:
    """
    Core TCP proxy engine.

    Usage (manual start/stop):
        engine = ProxyEngine(config)
        await engine.start()
        # ... proxy is listening ...
        await engine.stop()

    Usage (serve until done):
        await engine.serve_forever()   # blocks until stop() or Ctrl-C

    Dependencies are injected rather than constructed internally so that
    the engine is easy to test (pass in mock controllers, registries, etc.)
    and easy to compose at the ProxyAPI level.
    """

    def __init__(
        self,
        config:               ProxyConfig,
        tamper_controller: Optional[TamperController] = None,
        event_bus:            Optional[EventBus]            = None,
        session_registry:     Optional[SessionRegistry]     = None,
        rules_engine:         "Optional[RulesEngine]"       = None,
        forwarder_name:       str                           = "",
    ) -> None:
        """
        Args:
            config:            Network, framing, TLS, and interception settings.
            tamper_controller: Intercept/passthrough controller shared with the
                               ProxyAPI.  Defaults to PassthroughController (no
                               interception).
            event_bus:         Shared event bus for lifecycle events.  Defaults
                               to a new isolated bus.
            session_registry:  Shared registry for all sessions.  Defaults to a
                               new registry (isolated; useful in tests).
            rules_engine:      Replace rules engine.  None means no substitution.
            forwarder_name:    Human-readable label used in log messages and the
                               Traffic tab to identify which forwarder a session
                               came from.
        """
        self.config               = config
        self.forwarder_name       = forwarder_name
        # Use explicit is-None checks rather than truthiness (`or`) because
        # an empty SessionRegistry has __len__==0 which is falsy — using `or`
        # would silently create a second registry and break session tracking.
        self.tamper_controller = tamper_controller if tamper_controller is not None else PassthroughController()
        self.event_bus            = event_bus            if event_bus            is not None else EventBus()
        self.session_registry     = session_registry     if session_registry     is not None else SessionRegistry()
        self.rules_engine         = rules_engine

        # TLS handler — generates/loads the CA and builds SSL contexts.
        # setup() is called in start() so cert generation happens lazily.
        self.tls_handler = TLSHandler(config)

        # The asyncio server — set in start(), cleared in stop()
        self._server: Optional[asyncio.Server] = None

        # session_id → running asyncio Task
        # Used to cancel all sessions on shutdown.
        self._session_tasks: dict[str, asyncio.Task] = {}

        # session_id → StreamWriter to the upstream server.
        # Populated when a session becomes active; removed when it closes.
        # Used by inject_to_server() to write forged frames into an existing
        # proxied connection without opening a new TCP connection.
        self._session_server_writers: dict[str, asyncio.StreamWriter] = {}

        # session_id → StreamWriter to the client.
        # Populated when a session becomes active; removed when it closes.
        # Used by inject_to_client() to push data toward the client (simulating
        # server → client traffic from outside the normal relay path).
        self._session_client_writers: dict[str, asyncio.StreamWriter] = {}

        # session_id → BidirectionalRelay (active sessions only).
        # Used to hot-swap framers on running sessions without restarting.
        self._session_relays: dict[str, BidirectionalRelay] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """
        Start listening for connections.

        Returns as soon as the server is bound (does not block).
        The event loop must be running for connections to be handled.
        """
        # TLS setup is synchronous (cert generation); do it here so any errors
        # surface before we bind the listening socket.
        self.tls_handler.setup()

        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                host=self.config.listen_host,
                port=self.config.listen_port,
                ssl=self.tls_handler.get_listen_ssl_context(),
            )
        except OSError as exc:
            logger.error(
                "Forwarder '%s' failed to bind %s:%d: %s",
                self.forwarder_name,
                self.config.listen_host,
                self.config.listen_port,
                exc,
            )
            raise
        addrs = [str(s.getsockname()) for s in self._server.sockets]
        tls_info = ""
        if self.tls_handler.get_listen_ssl_context():
            tls_info = " [TLS listen]"
        if self.tls_handler.get_upstream_ssl_context():
            tls_info += " [TLS upstream]"
        logger.info(
            "Forwarder '%s' listening on %s → %s:%d%s",
            self.forwarder_name,
            addrs,
            self.config.upstream_host,
            self.config.upstream_port,
            tls_info,
        )

    async def serve_forever(self) -> None:
        """Start the server and block until stop() is called."""
        await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        """
        Gracefully shut down the proxy.

        1. Stops accepting new connections.
        2. Cancels all active session tasks.
        3. Shuts down the intercept controller (forwards pending items).
        """
        if self._server is not None:
            self._server.close()
            logger.info(
                "Forwarder '%s' stopped accepting connections",
                self.forwarder_name,
            )

        # Cancel all active sessions BEFORE calling wait_closed().
        # wait_closed() blocks until every open connection is gone — but those
        # connections are owned by the session tasks, so we must cancel the
        # tasks first; otherwise the two sides wait for each other forever.
        tasks = list(self._session_tasks.values())
        for task in tasks:
            task.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info("All %d session tasks cancelled", len(tasks))

        # All connections are now closed; wait_closed() returns immediately.
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

        await self.tamper_controller.shutdown()

    # ------------------------------------------------------------------
    # Connection handler (called by asyncio for each new client)
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """
        Entry point for each new incoming connection.

        asyncio calls this coroutine when a client connects. We do NOT
        await the relay here — instead we create a Task so this handler
        returns quickly and asyncio can accept more connections.
        """
        peer = client_writer.get_extra_info("peername") or ("unknown", 0)
        client_host, client_port = peer[0], peer[1]
        logger.info(
            "Client connected: %s:%d → forwarder '%s'",
            client_host, client_port, self.forwarder_name,
        )

        # Enforce session limit if configured
        if self.config.max_sessions > 0:
            active = len(self.session_registry.active_sessions())
            if active >= self.config.max_sessions:
                logger.warning(
                    "Session limit (%d) reached; rejecting %s:%d",
                    self.config.max_sessions, client_host, client_port,
                )
                client_writer.close()
                return

        # In auto-CA / transparent-proxy mode the TLS handshake is already
        # complete by the time asyncio calls this handler.  Extract the SNI
        # server_name the client declared so we can:
        #   a) record it as the logical server in the session
        #   b) forward it as the upstream TLS SNI (and hostname for verification)
        ssl_obj = client_writer.get_extra_info("ssl_object")
        sni_host = self.tls_handler.get_sni_hostname(ssl_obj)
        # Prefer the SNI hostname; fall back to the statically-configured host
        effective_server_name = sni_host or self.config.upstream_host
        if sni_host:
            logger.debug("SNI hostname from client: %s", sni_host)

        # Create session record
        session = self.session_registry.create(
            client_host=client_host,
            client_port=client_port,
            server_host=effective_server_name,
            server_port=self.config.upstream_port,
            forwarder_name=self.forwarder_name,
        )

        # Connect to upstream (always the configured IP/host for the TCP
        # connection, but pass the effective server name for TLS SNI and
        # hostname verification so the upstream handshake matches what the
        # client expects).
        upstream_ssl = self.tls_handler.get_upstream_ssl_context()

        try:
            server_reader, server_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.upstream_host,
                    self.config.upstream_port,
                    ssl=upstream_ssl,
                    # server_hostname drives both the TLS SNI extension sent to
                    # the upstream server and the hostname used for cert
                    # verification; ignored when ssl=None.
                    server_hostname=effective_server_name if upstream_ssl else None,
                ),
                timeout=self.config.connect_timeout,
            )
        except asyncio.TimeoutError:
            error_msg = (
                f"Timeout connecting to upstream "
                f"{self.config.upstream_host}:{self.config.upstream_port}"
            )
            logger.error("%s for session %s", error_msg, session.id[:8])
            client_writer.close()
            self.session_registry.mark_closed(session.id)
            await self.event_bus.publish(UpstreamConnectionFailedEvent(
                forwarder_name=self.forwarder_name,
                client_host=client_host,
                client_port=client_port,
                upstream_host=self.config.upstream_host,
                upstream_port=self.config.upstream_port,
                error=error_msg,
            ))
            return
        except OSError as exc:
            error_msg = str(exc)
            logger.error(
                "Failed to connect to upstream %s:%d for session %s: %s",
                self.config.upstream_host, self.config.upstream_port,
                session.id[:8], error_msg,
            )
            client_writer.close()
            self.session_registry.mark_closed(session.id)
            await self.event_bus.publish(UpstreamConnectionFailedEvent(
                forwarder_name=self.forwarder_name,
                client_host=client_host,
                client_port=client_port,
                upstream_host=self.config.upstream_host,
                upstream_port=self.config.upstream_port,
                error=error_msg,
            ))
            return

        # Both sides connected
        logger.info(
            "Connected to upstream %s:%d for session %s",
            self.config.upstream_host, self.config.upstream_port,
            session.id[:8],
        )
        self.session_registry.mark_active(session.id)
        self._session_server_writers[session.id] = server_writer
        self._session_client_writers[session.id] = client_writer
        await self.event_bus.publish(SessionOpenedEvent(session=session.info))


        # Create one framer per direction.
        # If a custom framer file is configured, load the factory and
        # instantiate both adapters with a shared state dict so the user
        # script can correlate client→server and server→client parsing.
        if self.config.custom_framer_path:
            framer_factory = load_framer_from_file(self.config.custom_framer_path)
            shared_state: dict = {}
            client_framer = framer_factory(session.id, Direction.CLIENT_TO_SERVER, shared_state)
            server_framer = framer_factory(session.id, Direction.SERVER_TO_CLIENT, shared_state)
        else:
            client_framer = create_framer(
                self.config.framer_name,
                session_id=session.id,
                direction=Direction.CLIENT_TO_SERVER,
                **self.config.framer_kwargs,
            )
            server_framer = create_framer(
                self.config.framer_name,
                session_id=session.id,
                direction=Direction.SERVER_TO_CLIENT,
                **self.config.framer_kwargs,
            )

        async def _on_first_disconnect(direction: Direction) -> None:
            if direction is Direction.CLIENT_TO_SERVER:
                self.session_registry.mark_only_server(session.id)
            else:
                self.session_registry.mark_only_client(session.id)
            await self.event_bus.publish(SessionUpdatedEvent(session=session.info))

        relay = BidirectionalRelay(
            session=session,
            client_reader=client_reader,
            client_writer=client_writer,
            server_reader=server_reader,
            server_writer=server_writer,
            client_framer=client_framer,
            server_framer=server_framer,
            tamper_controller=self.tamper_controller,
            event_bus=self.event_bus,
            read_buffer_size=self.config.read_buffer_size,
            rules_engine=self.rules_engine,
            on_first_disconnect=_on_first_disconnect,
        )

        # Track the relay so we can hot-swap framers on running sessions.
        self._session_relays[session.id] = relay

        # Run the relay as a tracked background task
        task = asyncio.create_task(
            self._run_session(session, relay),
            name=f"session-{session.id[:8]}",
        )
        self._session_tasks[session.id] = task

        # Remove from tracking dict when done
        task.add_done_callback(
            lambda _: self._session_tasks.pop(session.id, None)
        )

        # Note: we do NOT await the task here — the handler returns
        # immediately and asyncio continues accepting new connections.

    async def _run_session(self, session: Session, relay: BidirectionalRelay) -> None:
        """
        Run a session's relay and handle final cleanup.

        This is the Task body for each proxied connection.
        While the relay is running, partial-disconnect state updates (ONLY_SERVER /
        ONLY_CLIENT) are fired via the on_first_disconnect callback as soon as the
        first side closes.  After both sides fully close, the session is marked CLOSED.
        """
        try:
            await relay.run()
        except asyncio.CancelledError:
            logger.debug("Session %s cancelled", session.id[:8])
        except Exception as exc:
            logger.error("Session %s unhandled error: %s", session.id[:8], exc, exc_info=True)
        finally:
            self._session_server_writers.pop(session.id, None)
            self._session_client_writers.pop(session.id, None)
            self._session_relays.pop(session.id, None)
            self.session_registry.mark_closed(session.id)
            await self.event_bus.publish(SessionClosedEvent(session=session.info))
            logger.info(
                "Session %s closed (client %s:%d ↔ server %s:%d)",
                session.id[:8],
                session.info.client_host, session.info.client_port,
                session.info.server_host, session.info.server_port,
            )

    # ------------------------------------------------------------------
    # Hot-swap framers
    # ------------------------------------------------------------------

    def swap_framers_on_all_sessions(self) -> int:
        """
        Hot-swap the framer on every active session to match the current config.

        New framer instances are created from ``self.config`` (framer_name /
        framer_kwargs / custom_framer_path) and installed on each running
        relay.  Any partially-buffered bytes in the old framer are discarded
        (the new framer starts clean).

        Returns the number of sessions that were updated.
        """
        count = 0
        for session_id, relay in list(self._session_relays.items()):
            try:
                if self.config.custom_framer_path:
                    framer_factory = load_framer_from_file(self.config.custom_framer_path)
                    shared_state: dict = {}
                    client_framer = framer_factory(session_id, Direction.CLIENT_TO_SERVER, shared_state)
                    server_framer = framer_factory(session_id, Direction.SERVER_TO_CLIENT, shared_state)
                else:
                    client_framer = create_framer(
                        self.config.framer_name,
                        session_id=session_id,
                        direction=Direction.CLIENT_TO_SERVER,
                        **self.config.framer_kwargs,
                    )
                    server_framer = create_framer(
                        self.config.framer_name,
                        session_id=session_id,
                        direction=Direction.SERVER_TO_CLIENT,
                        **self.config.framer_kwargs,
                    )
                relay.swap_framers(client_framer, server_framer)
                count += 1
            except Exception as exc:
                logger.warning(
                    "Failed to swap framer on session %s: %s", session_id[:8], exc
                )
        if count:
            logger.info("Hot-swapped framer on %d active session(s)", count)
        return count

    # ------------------------------------------------------------------
    # Forge injection
    # ------------------------------------------------------------------

    async def terminate_session(self, session_id: str) -> bool:
        """
        Forcefully terminate an active session by cancelling its relay task.

        Cancelling the task triggers the ``_run_session`` finally block, which
        closes both the client and server TCP connections, marks the session
        CLOSED, and publishes a SessionClosedEvent.

        Returns:
            ``True``  if the session task was found and cancelled.
            ``False`` if the session is already closed (no task registered).
        """
        task = self._session_tasks.get(session_id)
        if task is None:
            return False
        task.cancel()
        logger.info("terminate_session: cancelled task for session %s", session_id[:8])
        return True

    def next_sequence_number(self, session_id: str, direction: Direction) -> int:
        """
        Allocate the next sequence number for *direction* in *session_id*.

        Delegates to the live framer so the counter stays in sync with
        normal relay-captured frames.  Falls back to the session frame count
        for that direction when no relay is active (e.g. forge sessions).
        """
        relay = self._session_relays.get(session_id)
        if relay is not None:
            return relay.framer_for(direction).next_sequence()
        session = self.session_registry.get(session_id)
        if session is not None:
            return len(session.frames_for_direction(direction))
        return 0

    async def inject_to_client(self, session_id: str, data: bytes) -> bool:
        """
        Write *data* directly into an active session's client TCP connection.

        The bytes are written to the client writer that the relay already holds
        open, so they arrive on the *same* TCP connection as the real server's
        traffic — the client sees them as if the server sent them.

        Returns:
            ``True``  if the session was found and the write succeeded.
            ``False`` if the session is not active (no writer registered).
        """
        writer = self._session_client_writers.get(session_id)
        if writer is None:
            return False
        writer.write(data)
        await writer.drain()
        logger.debug(
            "inject_to_client: injected %d bytes into session %s",
            len(data), session_id[:8],
        )
        return True

    async def inject_to_server(self, session_id: str, data: bytes) -> bool:
        """
        Write *data* directly into an active session's upstream TCP connection.

        The bytes are written to the server writer that the relay already holds
        open, so they arrive on the *same* TCP connection as the real client's
        traffic.  The server's response (if any) flows back through the normal
        relay path and is forwarded to the original client.

        Returns:
            ``True``  if the session was found and the write succeeded.
            ``False`` if the session is not active (no writer registered).

        Raises:
            OSError / BrokenPipeError: propagated if the write itself fails
            (caller should catch and treat as an injection error).
        """
        writer = self._session_server_writers.get(session_id)
        if writer is None:
            return False
        writer.write(data)
        await writer.drain()
        logger.debug(
            "inject_to_server: injected %d bytes into session %s",
            len(data), session_id[:8],
        )
        return True
