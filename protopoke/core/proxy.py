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
    - intercept/ (intercept queue and verdicts)

The engine just wires those pieces together for each new connection.

Concurrency model summary:
    - One asyncio server (asyncio.start_server) accepts connections.
    - Each session runs two Tasks (one per relay direction) created inside
      BidirectionalRelay.run(), plus one outer session Task in _run_session().
    - All Tasks share the same event loop — no threads, no locks needed for
      the session registry or intercept queue.

TLS future:
    To add TLS MITM, wrap the asyncio.open_connection() call with
    ssl.create_default_context() and do the same on the listening side with
    asyncio.start_server(..., ssl=server_ssl_context). The relay code doesn't
    need to change at all — it only sees StreamReader/StreamWriter.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, TYPE_CHECKING

from ..config import ProxyConfig
from ..models import Direction
from ..events.bus import EventBus, SessionOpenedEvent, SessionClosedEvent
from ..framing import create_framer
from ..intercept.controller import InterceptController, PassthroughController
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
        intercept_controller: Optional[InterceptController] = None,
        event_bus:            Optional[EventBus]            = None,
        session_registry:     Optional[SessionRegistry]     = None,
        rules_engine:         "Optional[RulesEngine]"       = None,
    ) -> None:
        self.config               = config
        # Use explicit is-None checks rather than truthiness (`or`) because
        # an empty SessionRegistry has __len__==0 which is falsy — using `or`
        # would silently create a second registry and break session tracking.
        self.intercept_controller = intercept_controller if intercept_controller is not None else PassthroughController()
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

        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.config.listen_host,
            port=self.config.listen_port,
            ssl=self.tls_handler.get_listen_ssl_context(),
        )
        addrs = [str(s.getsockname()) for s in self._server.sockets]
        logger.info(
            "Proxy listening on %s → %s:%d",
            addrs,
            self.config.upstream_host,
            self.config.upstream_port,
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
            await self._server.wait_closed()
            self._server = None
            logger.info("Proxy server stopped accepting connections")

        # Cancel all active sessions
        tasks = list(self._session_tasks.values())
        for task in tasks:
            task.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info("All %d session tasks cancelled", len(tasks))

        await self.intercept_controller.shutdown()

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
        logger.info("New client: %s:%d", client_host, client_port)

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
            logger.error(
                "Timeout connecting to upstream %s:%d for session %s",
                self.config.upstream_host, self.config.upstream_port,
                session.id,
            )
            client_writer.close()
            self.session_registry.mark_closed(session.id)
            return
        except OSError as exc:
            logger.error(
                "Failed to connect to upstream %s:%d for session %s: %s",
                self.config.upstream_host, self.config.upstream_port,
                session.id, exc,
            )
            client_writer.close()
            self.session_registry.mark_closed(session.id)
            return

        # Both sides connected
        self.session_registry.mark_active(session.id)
        await self.event_bus.publish(SessionOpenedEvent(session=session.info))

        # Create one framer per direction
        # framer_kwargs let the user pass extra config (e.g. delimiter bytes)
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

        relay = BidirectionalRelay(
            session=session,
            client_reader=client_reader,
            client_writer=client_writer,
            server_reader=server_reader,
            server_writer=server_writer,
            client_framer=client_framer,
            server_framer=server_framer,
            intercept_controller=self.intercept_controller,
            event_bus=self.event_bus,
            read_buffer_size=self.config.read_buffer_size,
            rules_engine=self.rules_engine,
        )

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
        """
        try:
            await relay.run()
        except asyncio.CancelledError:
            logger.debug("Session %s cancelled", session.id)
        except Exception as exc:
            logger.error("Session %s unhandled error: %s", session.id, exc, exc_info=True)
        finally:
            self.session_registry.mark_closed(session.id)
            await self.event_bus.publish(SessionClosedEvent(session=session.info))
            logger.info("Session %s done", session.id)
