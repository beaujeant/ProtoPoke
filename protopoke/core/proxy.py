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

from ..config import ForwarderConfig, ForwarderType
from ..models import Direction, SessionState
from ..events.bus import EventBus, SessionOpenedEvent, SessionClosedEvent, SessionUpdatedEvent, UpstreamConnectionFailedEvent
from ..framing import create_framer, load_framer_from_file
from ..framing.raw import RawFramer
from ..tamper.controller import TamperController, PassthroughController
from ..tls.handler import TLSHandler
from .session import SessionRegistry, Session
from .relay import BidirectionalRelay
from . import socks5
from .udp_proxy import UdpFlow, _UdpServerProtocol, _UdpUpstreamProtocol, process_udp_datagram

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
    and easy to compose at the ProtoPokeAPI level.
    """

    def __init__(
        self,
        config:               ForwarderConfig,
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
                               ProtoPokeAPI.  Defaults to PassthroughController (no
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

        # ----- UDP-only state -----
        # The shared listening DatagramTransport (one per UDP forwarder).
        self._udp_listen_transport: Optional[asyncio.DatagramTransport] = None
        # client_addr (host, port) → UdpFlow
        self._udp_flows_by_addr: dict[tuple[str, int], UdpFlow] = {}
        # session_id → UdpFlow  (mirror lookup for inject_to_*, terminate_session)
        self._udp_flows: dict[str, UdpFlow] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """
        Start listening for connections.

        Returns as soon as the listener is bound (does not block).
        The event loop must be running for traffic to be handled.

        Dispatches on ``config.forwarder_type``:
            - TCP   : `asyncio.start_server` accepting BidirectionalRelay sessions.
            - UDP   : `loop.create_datagram_endpoint` + per-flow upstream sockets.
            - SOCKS5: same as TCP but each connection performs a SOCKS5 handshake
                      to discover the per-connection upstream target.
        """
        # TLS setup is synchronous (cert generation); do it here so any errors
        # surface before we bind the listening socket.
        self.tls_handler.setup()

        if self.config.forwarder_type is ForwarderType.UDP:
            await self._start_udp()
        elif self.config.forwarder_type is ForwarderType.SOCKS5:
            await self._start_socks5()
        else:
            await self._start_tcp()

    async def _start_tcp(self) -> None:
        """Start a plain TCP forwarder (current default behaviour)."""
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
            "Forwarder '%s' [tcp] listening on %s → %s:%d%s",
            self.forwarder_name,
            addrs,
            self.config.upstream_host,
            self.config.upstream_port,
            tls_info,
        )

    async def _start_socks5(self) -> None:
        """Start a SOCKS5 proxy forwarder."""
        try:
            self._server = await asyncio.start_server(
                self._handle_socks5_client,
                host=self.config.listen_host,
                port=self.config.listen_port,
                ssl=None,  # SOCKS5 + TLS-listen is rejected in ForwarderConfig
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
        auth_info = " [auth=user/pass]" if self.config.socks_auth_user else " [auth=none]"
        logger.info(
            "Forwarder '%s' [socks5] listening on %s%s",
            self.forwarder_name, addrs, auth_info,
        )

    async def _start_udp(self) -> None:
        """Start a UDP forwarder."""
        loop = asyncio.get_event_loop()
        try:
            transport, _proto = await loop.create_datagram_endpoint(
                lambda: _UdpServerProtocol(self),
                local_addr=(self.config.listen_host, self.config.listen_port),
            )
        except OSError as exc:
            logger.error(
                "Forwarder '%s' [udp] failed to bind %s:%d: %s",
                self.forwarder_name,
                self.config.listen_host,
                self.config.listen_port,
                exc,
            )
            raise
        self._udp_listen_transport = transport
        logger.info(
            "Forwarder '%s' [udp] listening on %s:%d → %s:%d",
            self.forwarder_name,
            self.config.listen_host, self.config.listen_port,
            self.config.upstream_host, self.config.upstream_port,
        )

    async def serve_forever(self) -> None:
        """Start the server and block until stop() is called."""
        await self.start()
        if self._server is not None:
            async with self._server:
                await self._server.serve_forever()
        else:
            # UDP path: no asyncio.Server; just wait until stop() cancels us.
            try:
                while self._udp_listen_transport is not None:
                    await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass

    async def stop(self) -> None:
        """
        Gracefully shut down the proxy.

        1. Stops accepting new connections / datagrams.
        2. Cancels all active session tasks and closes UDP flows.
        3. Shuts down the intercept controller (forwards pending items).
        """
        if self._server is not None:
            self._server.close()
            logger.info(
                "Forwarder '%s' stopped accepting connections",
                self.forwarder_name,
            )

        if self._udp_listen_transport is not None:
            try:
                self._udp_listen_transport.close()
            except Exception:
                pass
            self._udp_listen_transport = None

        # Close all UDP flows (publishes SessionClosedEvent for each).
        for flow in list(self._udp_flows.values()):
            await self._close_udp_flow(flow, reason="shutdown")

        # Cancel all active TCP sessions BEFORE calling wait_closed().
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
        Entry point for each new TCP connection.

        Resolves the upstream target via SNI (when TLS-MITM is active) or
        falls back to the configured ``upstream_host``/``upstream_port``,
        then hands off to :meth:`_run_tcp_session`.
        """
        peer = client_writer.get_extra_info("peername") or ("unknown", 0)
        client_host, client_port = peer[0], peer[1]
        logger.info(
            "Client connected: %s:%d → forwarder '%s'",
            client_host, client_port, self.forwarder_name,
        )

        if not self._enforce_session_limit(client_writer, client_host, client_port):
            return

        # In auto-CA / transparent-proxy mode the TLS handshake is already
        # complete by the time asyncio calls this handler.  Extract the SNI
        # server_name the client declared so we can:
        #   a) record it as the logical server in the session
        #   b) forward it as the upstream TLS SNI (and hostname for verification)
        ssl_obj = client_writer.get_extra_info("ssl_object")
        sni_host = self.tls_handler.get_sni_hostname(ssl_obj)
        effective_server_name = sni_host or self.config.upstream_host
        if sni_host:
            logger.debug("SNI hostname from client: %s", sni_host)

        await self._run_tcp_session(
            client_reader=client_reader,
            client_writer=client_writer,
            client_host=client_host,
            client_port=client_port,
            connect_host=self.config.upstream_host,
            connect_port=self.config.upstream_port,
            display_host=effective_server_name,
            display_port=self.config.upstream_port,
            tls_server_name=effective_server_name,
            transport="tcp",
        )

    async def _handle_socks5_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """
        Entry point for SOCKS5 connections.

        Performs RFC 1928 + RFC 1929 negotiation, then runs the same
        TCP relay code as :meth:`_handle_client` against the
        client-supplied target.
        """
        peer = client_writer.get_extra_info("peername") or ("unknown", 0)
        client_host, client_port = peer[0], peer[1]
        logger.info(
            "SOCKS5 client connected: %s:%d → forwarder '%s'",
            client_host, client_port, self.forwarder_name,
        )

        if not self._enforce_session_limit(client_writer, client_host, client_port):
            return

        try:
            target_host, target_port = await socks5.negotiate(
                client_reader,
                client_writer,
                self.config.socks_auth_user,
                self.config.socks_auth_pass,
            )
        except socks5.Socks5Error as exc:
            logger.warning(
                "SOCKS5 handshake failed for %s:%d: %s",
                client_host, client_port, exc,
            )
            try:
                await socks5.send_reply(client_writer, exc.reply)
            except Exception:
                pass
            client_writer.close()
            return
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as exc:
            logger.debug(
                "SOCKS5 client %s:%d disconnected during handshake: %s",
                client_host, client_port, exc,
            )
            client_writer.close()
            return

        logger.info(
            "SOCKS5 CONNECT %s:%d (client %s:%d, forwarder '%s')",
            target_host, target_port, client_host, client_port, self.forwarder_name,
        )

        await self._run_tcp_session(
            client_reader=client_reader,
            client_writer=client_writer,
            client_host=client_host,
            client_port=client_port,
            connect_host=target_host,
            connect_port=target_port,
            display_host=target_host,
            display_port=target_port,
            tls_server_name=target_host,
            transport="socks5",
            socks5_reply=True,
        )

    def _enforce_session_limit(
        self,
        client_writer: asyncio.StreamWriter,
        client_host: str,
        client_port: int,
    ) -> bool:
        """Return True if the new connection is allowed under max_sessions."""
        if self.config.max_sessions > 0:
            active = len(self.session_registry.active_sessions())
            if active >= self.config.max_sessions:
                logger.warning(
                    "Session limit (%d) reached; rejecting %s:%d",
                    self.config.max_sessions, client_host, client_port,
                )
                client_writer.close()
                return False
        return True

    async def _run_tcp_session(
        self,
        *,
        client_reader:  asyncio.StreamReader,
        client_writer:  asyncio.StreamWriter,
        client_host:    str,
        client_port:    int,
        connect_host:   str,
        connect_port:   int,
        display_host:   str,
        display_port:   int,
        tls_server_name: str,
        transport:      str = "tcp",
        socks5_reply:   bool = False,
    ) -> None:
        """
        Open the upstream TCP connection and run a BidirectionalRelay session.

        Used by both plain TCP forwarders and SOCKS5 forwarders. The split
        between ``connect_*`` (where we open the socket) and ``display_*``
        (what we record on the session) is what lets transparent-MITM TCP
        keep its statically-configured upstream IP while showing the
        SNI-derived hostname in the Traffic tab.
        """
        session = self.session_registry.create(
            client_host=client_host,
            client_port=client_port,
            server_host=display_host,
            server_port=display_port,
            forwarder_name=self.forwarder_name,
            transport=transport,
        )

        upstream_ssl = self.tls_handler.get_upstream_ssl_context()

        try:
            server_reader, server_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    connect_host,
                    connect_port,
                    ssl=upstream_ssl,
                    server_hostname=tls_server_name if upstream_ssl else None,
                ),
                timeout=self.config.connect_timeout,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            if isinstance(exc, asyncio.TimeoutError):
                error_msg = f"Timeout connecting to upstream {connect_host}:{connect_port}"
                reply = socks5.Socks5Reply.TTL_EXPIRED
            else:
                error_msg = str(exc)
                reply = socks5.reply_for_oserror(exc)
            logger.error("%s for session %s", error_msg, session.id[:8])
            if socks5_reply:
                try:
                    await socks5.send_reply(client_writer, reply)
                except Exception:
                    pass
            client_writer.close()
            self.session_registry.mark_closed(session.id)
            await self.event_bus.publish(UpstreamConnectionFailedEvent(
                forwarder_name=self.forwarder_name,
                client_host=client_host,
                client_port=client_port,
                upstream_host=connect_host,
                upstream_port=connect_port,
                error=error_msg,
            ))
            return

        if socks5_reply:
            sockname = server_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
            try:
                await socks5.send_reply(
                    client_writer,
                    socks5.Socks5Reply.SUCCEEDED,
                    bnd_host=str(sockname[0]),
                    bnd_port=int(sockname[1]),
                )
            except Exception as exc:
                logger.debug("Failed to send SOCKS5 success reply: %s", exc)
                client_writer.close()
                server_writer.close()
                self.session_registry.mark_closed(session.id)
                return

        logger.info(
            "Connected to upstream %s:%d for session %s",
            connect_host, connect_port, session.id[:8],
        )
        self.session_registry.mark_active(session.id)
        self._session_server_writers[session.id] = server_writer
        self._session_client_writers[session.id] = client_writer
        await self.event_bus.publish(SessionOpenedEvent(session=session.info))

        # Create one framer per direction.
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
            keep_upstream_on_client_disconnect=self.config.keep_upstream_on_client_disconnect,
            keep_client_on_server_disconnect=self.config.keep_client_on_server_disconnect,
        )

        self._session_relays[session.id] = relay

        task = asyncio.create_task(
            self._run_session(session, relay),
            name=f"session-{session.id[:8]}",
        )
        self._session_tasks[session.id] = task

        task.add_done_callback(
            lambda _: self._session_tasks.pop(session.id, None)
        )

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
        Forcefully terminate an active session.

        For TCP/SOCKS5: cancels the relay task, which triggers cleanup,
        connection close, mark CLOSED, and SessionClosedEvent.
        For UDP: closes the per-flow upstream socket and marks the session
        CLOSED via :meth:`_close_udp_flow`.

        Returns ``True`` if a session was found and terminated, ``False``
        if it was already closed.
        """
        flow = self._udp_flows.get(session_id)
        if flow is not None:
            await self._close_udp_flow(flow, reason="terminated")
            logger.info("terminate_session: closed UDP flow for session %s", session_id[:8])
            return True
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
        Push *data* into an active session toward the client.

        For TCP/SOCKS5: writes to the relay's client StreamWriter — the
        client sees the bytes as if the server sent them.
        For UDP: ``sendto(data, flow.client_addr)`` on the listening socket.

        Returns ``True`` on success, ``False`` if the session is not active.
        """
        flow = self._udp_flows.get(session_id)
        if flow is not None and not flow.closed:
            try:
                flow.listen_transport.sendto(data, flow.client_addr)
            except OSError as exc:
                logger.debug("UDP inject_to_client failed: %s", exc)
                return False
            logger.debug(
                "inject_to_client: sent %d UDP bytes to session %s",
                len(data), session_id[:8],
            )
            return True

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
        Push *data* into an active session toward the upstream server.

        For TCP/SOCKS5: writes to the relay's server StreamWriter — the
        upstream sees the bytes as if the client sent them. The server's
        response (if any) flows back through the normal relay path.
        For UDP: ``sendto(data)`` on the per-flow upstream socket (which is
        bound with ``remote_addr``, so no explicit destination is needed).

        Returns ``True`` on success, ``False`` if the session is not active.
        """
        flow = self._udp_flows.get(session_id)
        if flow is not None and not flow.closed:
            try:
                flow.upstream_transport.sendto(data)
            except OSError as exc:
                logger.debug("UDP inject_to_server failed: %s", exc)
                return False
            logger.debug(
                "inject_to_server: sent %d UDP bytes to session %s",
                len(data), session_id[:8],
            )
            return True

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

    # ------------------------------------------------------------------
    # UDP-specific handlers
    # ------------------------------------------------------------------

    async def _on_udp_client_datagram(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        """Handle a datagram received from a client (UDP forwarder)."""
        flow = self._udp_flows_by_addr.get(addr)
        if flow is None:
            flow = await self._open_udp_flow(addr)
            if flow is None:
                return  # upstream open failed; flow not created
        if flow.closed:
            return  # raced with idle sweeper; drop

        out_bytes = await process_udp_datagram(self, flow, data, Direction.CLIENT_TO_SERVER)
        if out_bytes is None:
            return
        try:
            flow.upstream_transport.sendto(out_bytes)
        except OSError as exc:
            logger.debug(
                "UDP upstream sendto failed for session %s: %s",
                flow.session.id[:8], exc,
            )

    async def _on_udp_server_datagram(
        self,
        session_id: str,
        data: bytes,
    ) -> None:
        """Handle a datagram received from upstream (UDP forwarder)."""
        flow = self._udp_flows.get(session_id)
        if flow is None or flow.closed:
            return
        out_bytes = await process_udp_datagram(self, flow, data, Direction.SERVER_TO_CLIENT)
        if out_bytes is None:
            return
        try:
            flow.listen_transport.sendto(out_bytes, flow.client_addr)
        except OSError as exc:
            logger.debug(
                "UDP listen sendto failed for session %s: %s",
                flow.session.id[:8], exc,
            )

    async def _open_udp_flow(self, addr: tuple[str, int]) -> Optional[UdpFlow]:
        """
        Create a new UDP flow for a previously-unseen client address.

        Opens the per-flow upstream DatagramTransport, registers the flow,
        creates the Session record, and publishes SessionOpenedEvent.
        Returns ``None`` if the upstream endpoint cannot be created.
        """
        if self._udp_listen_transport is None:
            return None

        if self.config.max_sessions > 0:
            active = len(self.session_registry.active_sessions())
            if active >= self.config.max_sessions:
                logger.warning(
                    "Session limit (%d) reached; dropping UDP packet from %s:%d",
                    self.config.max_sessions, addr[0], addr[1],
                )
                return None

        client_host, client_port = addr[0], addr[1]
        session = self.session_registry.create(
            client_host=client_host,
            client_port=client_port,
            server_host=self.config.upstream_host,
            server_port=self.config.upstream_port,
            forwarder_name=self.forwarder_name,
            transport="udp",
        )

        loop = asyncio.get_event_loop()
        try:
            upstream_transport, _proto = await loop.create_datagram_endpoint(
                lambda: _UdpUpstreamProtocol(self, session.id),
                remote_addr=(self.config.upstream_host, self.config.upstream_port),
            )
        except OSError as exc:
            error_msg = str(exc)
            logger.error(
                "Failed to open UDP upstream %s:%d for session %s: %s",
                self.config.upstream_host, self.config.upstream_port,
                session.id[:8], error_msg,
            )
            self.session_registry.mark_closed(session.id)
            await self.event_bus.publish(UpstreamConnectionFailedEvent(
                forwarder_name=self.forwarder_name,
                client_host=client_host,
                client_port=client_port,
                upstream_host=self.config.upstream_host,
                upstream_port=self.config.upstream_port,
                error=error_msg,
            ))
            return None

        client_framer = RawFramer(session_id=session.id, direction=Direction.CLIENT_TO_SERVER)
        server_framer = RawFramer(session_id=session.id, direction=Direction.SERVER_TO_CLIENT)

        flow = UdpFlow(
            session=session,
            listen_transport=self._udp_listen_transport,
            upstream_transport=upstream_transport,
            client_addr=addr,
            client_framer=client_framer,
            server_framer=server_framer,
        )
        self._udp_flows_by_addr[addr] = flow
        self._udp_flows[session.id] = flow

        self.session_registry.mark_active(session.id)
        await self.event_bus.publish(SessionOpenedEvent(session=session.info))
        logger.info(
            "UDP flow opened: %s:%d → %s:%d (session %s)",
            client_host, client_port,
            self.config.upstream_host, self.config.upstream_port,
            session.id[:8],
        )
        return flow

    async def _close_udp_flow(self, flow: UdpFlow, reason: str) -> None:
        """Close a UDP flow: close upstream socket, mark CLOSED, publish event."""
        if flow.closed:
            return
        flow.closed = True
        try:
            flow.upstream_transport.close()
        except Exception:
            pass

        # Remove from lookup tables before publishing — the SessionClosedEvent
        # may trigger UI updates that re-query state.
        self._udp_flows_by_addr.pop(flow.client_addr, None)
        self._udp_flows.pop(flow.session.id, None)

        if flow.session.info.state is not SessionState.CLOSED:
            self.session_registry.mark_closed(flow.session.id)
            await self.event_bus.publish(SessionClosedEvent(session=flow.session.info))
        logger.info(
            "UDP flow closed (%s): session %s (%d frames captured)",
            reason, flow.session.id[:8], len(flow.session.frames),
        )
