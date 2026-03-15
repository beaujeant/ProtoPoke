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
    - The intercept controller always uses QueuedInterceptController, with
      config.intercept_enabled controlling its initial on/off state. This allows
      toggling interception at runtime regardless of the startup config value.

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
from pathlib import Path
from typing import Any, Callable, Optional

from .config import ProxyConfig
from .models import Direction, Frame, InterceptedUnit, ParsedMessage
from .core.proxy import ProxyEngine
from .core.session import Session, SessionRegistry
from .tls.ca import CertificateAuthority
from .tls.handler import TLSHandler
from .events.bus import (
    EventBus,
    SessionOpenedEvent,
    SessionClosedEvent,
    FrameCapturedEvent,
)
from .intercept.controller import QueuedInterceptController
from .replay.engine import ReplayEngine, ReplayResult
from .replay.models import SendRecord, RepeaterRequest
from .rules.engine import RulesEngine, InterceptFilter
from .rules.rule import ReplaceRule, InterceptRule
from .storage.base import StorageBackend, NullStorageBackend
from .protocol.base import ProtocolDecoder, ProtocolEncoder, PassthroughDecoder
from .fuzzing.models import FuzzCampaign, FuzzResult
from .fuzzing.engine import FuzzerEngine
from .fuzzing.mutators.base import FrameMutator
from .sequencer.models import HistoryEntry, SequencerSession
from .sequencer.engine import SequencerEngine, load_script

logger = logging.getLogger(__name__)


class ProxyAPI:
    """
    High-level control interface for the TCP proxy.

    Instantiate with a ProxyConfig, then call start()/stop() or
    serve_forever() to run the proxy.
    """

    def __init__(
        self,
        config:           ProxyConfig,
        storage:          Optional[StorageBackend] = None,
        rules_engine:     Optional[RulesEngine]    = None,
        intercept_filter: Optional[InterceptFilter] = None,
    ) -> None:
        self.config = config

        # Shared infrastructure
        self.event_bus        = EventBus()
        self.session_registry = SessionRegistry()
        self.storage          = storage or NullStorageBackend()

        # Rules engines (replace rules + intercept rules)
        self.rules_engine     = rules_engine     or RulesEngine()
        self.intercept_filter = intercept_filter or InterceptFilter()

        # Always use QueuedInterceptController; config.intercept_enabled sets
        # the initial on/off state so it can be toggled at any time.
        self._intercept_controller: QueuedInterceptController
        self._intercept_controller = QueuedInterceptController(
            intercept_enabled=config.intercept_enabled,
            intercept_filter=self.intercept_filter,
        )

        # Core engine (passes rules_engine to relay)
        self.engine = ProxyEngine(
            config=config,
            intercept_controller=self._intercept_controller,
            event_bus=self.event_bus,
            session_registry=self.session_registry,
            rules_engine=self.rules_engine,
        )

        # Replay engine
        self.replay_engine = ReplayEngine(
            session_registry=self.session_registry,
            connect_timeout=config.connect_timeout,
            framer_name=config.framer_name,
            framer_kwargs=config.framer_kwargs,
        )

        # Protocol decoder/encoder (lazy-loaded)
        self._decoder: ProtocolDecoder = PassthroughDecoder()
        self._encoder: Optional[ProtocolEncoder] = None

        # Fuzzer engine (lazy-constructed on first use)
        self._fuzzer_engine: Optional[FuzzerEngine] = None

    # ------------------------------------------------------------------
    # TLS helpers
    # ------------------------------------------------------------------

    @property
    def tls_handler(self) -> TLSHandler:
        """The TLSHandler owned by the engine (CA, SSL contexts, etc.)."""
        return self.engine.tls_handler

    @property
    def ca(self) -> Optional[CertificateAuthority]:
        """
        The active Certificate Authority, or None when TLS is not in auto-CA
        mode (i.e. tls_listen=False or a manual cert was supplied).

        Use this to export the CA cert so clients can trust it::

            with open("protopoke-ca.crt", "wb") as f:
                f.write(api.ca.cert_pem)
        """
        return self.engine.tls_handler.ca

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start listening for connections (non-blocking)."""
        # Auto-load protocol definition if configured
        if self.config.protocol_definition_path:
            self.set_protocol_file(self.config.protocol_definition_path)

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

    async def terminate_session(self, session_id: str) -> bool:
        """
        Forcefully close an active session.

        Cancels the session's relay task, which closes both the client and
        server TCP connections and marks the session CLOSED.  If the session
        is already closed (or not found) this is a no-op and returns ``False``.

        Returns:
            ``True``  if the session was active and has been cancelled.
            ``False`` if the session is already closed or does not exist.
        """
        return await self.engine.terminate_session(session_id)

    def delete_session(self, session_id: str) -> bool:
        """
        Permanently remove a session (and all its frames) from the registry.

        This only removes the in-memory record; it does **not** close the
        underlying connection.  Terminate the session first if it is still
        active, then call this to clean up the log.

        Returns:
            ``True``  if the session existed and was removed.
            ``False`` if the session was not found.
        """
        return self.session_registry.delete(session_id)

    def load_sessions_from_dicts(self, sessions_data: list[dict]) -> list[Session]:
        """
        Restore saved sessions into the registry (used when loading a project).

        Each dict must have the shape produced by ``session_to_dict()``:
        keys: id, client_host, client_port, server_host, server_port, state,
        created_at, closed_at (optional), frames (list of frame dicts).

        Returns the list of restored Session objects.
        """
        from .models import SessionInfo, SessionState, Frame, Direction
        restored: list[Session] = []
        for sd in sessions_data:
            info = SessionInfo(
                id=sd["id"],
                client_host=sd.get("client_host", ""),
                client_port=sd.get("client_port", 0),
                server_host=sd.get("server_host", ""),
                server_port=sd.get("server_port", 0),
                state=SessionState(sd.get("state", "closed")),
                created_at=sd.get("created_at", 0.0),
                closed_at=sd.get("closed_at"),
            )
            session = Session(info)
            for fd in sd.get("frames", []):
                frame = Frame(
                    id=fd["id"],
                    session_id=fd["session_id"],
                    direction=Direction(fd["direction"]),
                    raw_bytes=bytes.fromhex(fd["raw_bytes"]),
                    timestamp=fd["timestamp"],
                    sequence_number=fd["sequence_number"],
                    framer_name=fd.get("framer_name", "raw"),
                )
                session.frames.append(frame)
            self.session_registry._sessions[session.id] = session
            restored.append(session)
        return restored

    @staticmethod
    def session_to_dict(session: Session) -> dict:
        """Serialise a Session (info + frames) to a JSON-compatible dict."""
        d = session.info.to_dict()
        d["frames"] = [f.to_dict() for f in session.frames]
        return d

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
        return self._intercept_controller.intercept_enabled

    @intercept_enabled.setter
    def intercept_enabled(self, value: bool) -> None:
        """
        Enable or disable interception at runtime.

        When disabled, all currently pending frames are immediately forwarded.
        When enabled, subsequent frames are held for operator review.
        """
        self._intercept_controller.intercept_enabled = value

    async def get_next_intercepted(self) -> InterceptedUnit:
        """
        Wait for and return the next intercepted frame.

        Blocks until a frame arrives in the intercept queue.

        Raises:
            RuntimeError: if interception is not enabled.
        """
        return await self._intercept_controller.get_pending()

    def list_intercepted(self) -> list[InterceptedUnit]:
        """Snapshot of all frames currently waiting for a verdict."""
        return self._intercept_controller.list_pending()

    def pending_count(self) -> int:
        """Number of frames waiting for an intercept verdict."""
        return self._intercept_controller.pending_count()

    def forward(self, unit_id: str) -> bool:
        """Forward an intercepted frame as-is."""
        return self._intercept_controller.forward(unit_id)

    def drop(self, unit_id: str) -> bool:
        """Drop an intercepted frame (don't forward it)."""
        return self._intercept_controller.drop(unit_id)

    def modify_and_forward(self, unit_id: str, new_data: bytes) -> bool:
        """Forward an intercepted frame with replacement bytes."""
        return self._intercept_controller.modify_and_forward(unit_id, new_data)

    def forward_all(self) -> int:
        """Forward all currently pending intercepted frames. Returns count."""
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
        direction:       Direction                  = Direction.CLIENT_TO_SERVER,
        frame_selector:  Optional[str]              = None,
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
            direction:       Which direction's frames to source for replay.
                             Default: CLIENT_TO_SERVER (replay what the client sent).
                             Use SERVER_TO_CLIENT to replay server-side frames.
            frame_selector:  Selector string to pick specific frames by sequence
                             number within the chosen direction. Examples:
                               "5"          — only sequence 5
                               "3-13"       — sequences 3 through 13 inclusive
                               "3,4,7"      — sequences 3, 4 and 7
                               "3,5,7-9,11" — sequences 3, 5, 7, 8, 9 and 11
                             None (default) means all frames in that direction.

        Returns:
            ReplayResult with the new replayed session and metadata.
        """
        return await self.replay_engine.replay_session(
            session_id=session_id,
            server_host=server_host,
            server_port=server_port,
            frame_delay=frame_delay,
            modified_frames=modified_frames,
            direction=direction,
            frame_selector=frame_selector,
        )

    # ------------------------------------------------------------------
    # Protocol decoder/encoder
    # ------------------------------------------------------------------

    def set_protocol(
        self,
        decoder: ProtocolDecoder,
        encoder: Optional[ProtocolEncoder] = None,
    ) -> None:
        """
        Attach a protocol decoder (and optionally encoder) to this API instance.

        The decoder is used by decode_frame() and get_next_intercepted_parsed().
        The encoder is used by modify_field_and_forward() and replay with field edits.

        Args:
            decoder: A ProtocolDecoder instance (e.g. DefinitionBasedDecoder).
            encoder: Optional matching ProtocolEncoder.  Required for field-level
                     editing.  If not provided, raw-bytes editing still works.
        """
        self._decoder = decoder
        self._encoder = encoder
        logger.info("Protocol set: %s", decoder.protocol_name)

    def set_protocol_file(self, path: str) -> None:
        """
        Load a protocol definition from a YAML or JSON file and attach it.

        Convenience wrapper around set_protocol() that handles loading.

        Args:
            path: Path to a .yaml, .yml, or .json protocol definition file.

        Raises:
            FileNotFoundError: File not found.
            ImportError:       YAML file but PyYAML not installed.
            ValueError:        File is malformed.
        """
        from .protocol.definition import load_protocol_file
        from .protocol.parser import DefinitionBasedDecoder, DefinitionBasedEncoder

        defn = load_protocol_file(path)
        decoder = DefinitionBasedDecoder(defn)
        encoder = DefinitionBasedEncoder(defn)
        self.set_protocol(decoder, encoder)
        logger.info("Protocol definition loaded from %s: %s", path, defn.name)

    def set_protocol_dict(self, raw: dict) -> None:
        """
        Load a protocol definition from a raw dict and attach it.

        Useful when building definitions programmatically in tests or scripts.

        Args:
            raw: Protocol definition as a dict (same structure as the YAML).
        """
        from .protocol.definition import load_protocol
        from .protocol.parser import DefinitionBasedDecoder, DefinitionBasedEncoder

        defn = load_protocol(raw)
        self.set_protocol(DefinitionBasedDecoder(defn), DefinitionBasedEncoder(defn))

    def decode_frame(self, frame: Frame) -> ParsedMessage:
        """
        Decode a captured frame using the currently attached protocol decoder.

        Args:
            frame: Any Frame object (from get_frames() or an intercepted unit).

        Returns:
            ParsedMessage with structured fields, offset metadata, and display values.
            Always returns successfully — partial results with error set on failure.
        """
        return self._decoder.decode(frame)

    def decode_session_frames(
        self,
        session_id: str,
        direction:  Optional[Direction] = None,
    ) -> list[ParsedMessage]:
        """
        Decode all frames in a session and return them as ParsedMessages.

        Args:
            session_id: The session to query.
            direction:  If set, filter to one direction only.

        Returns:
            List of ParsedMessage in capture order.
        """
        frames = self.get_frames(session_id, direction)
        return [self._decoder.decode(f) for f in frames]

    async def get_next_intercepted_parsed(self) -> tuple[InterceptedUnit, ParsedMessage]:
        """
        Wait for and return the next intercepted frame, with its parsed view.

        Like get_next_intercepted() but also decodes the frame using the
        attached protocol decoder.

        Returns:
            (InterceptedUnit, ParsedMessage) tuple.

        Raises:
            RuntimeError: if interception is not enabled.
        """
        unit = await self.get_next_intercepted()
        msg  = self._decoder.decode(unit.frame)
        return unit, msg

    def modify_field_and_forward(
        self,
        unit_id:    str,
        field_edits: dict[str, Any],
    ) -> bool:
        """
        Re-encode an intercepted frame with field-level edits, then forward it.

        Requires an encoder to be set (via set_protocol() or set_protocol_file()).
        Falls back to raw-byte forwarding if no encoder is available.

        Args:
            unit_id:     ID of the intercepted unit to act on.
            field_edits: Dict of field_name → new value.
                         Values can be int, str, or bytes depending on the field type.

        Returns:
            True if the verdict was applied, False if unit_id not found.
        """
        unit = self._intercept_controller.get_by_id(unit_id)
        if unit is None:
            return False

        if self._encoder is None:
            logger.warning(
                "modify_field_and_forward: no encoder set, falling back to raw-bytes edit. "
                "Call set_protocol_file() to enable field-level encoding."
            )
            return False

        try:
            from .protocol.parser.engine import DefinitionBasedEncoder
            if not isinstance(self._encoder, DefinitionBasedEncoder):
                logger.warning("modify_field_and_forward: encoder does not support field edits")
                return False

            msg = self._decoder.decode(unit.frame)
            new_bytes = self._encoder.encode_with_edits(msg, field_edits)
            return self._intercept_controller.modify_and_forward(unit_id, new_bytes)
        except Exception as exc:
            logger.error("modify_field_and_forward failed: %s", exc, exc_info=True)
            return False

    async def replay_session_with_field_edits(
        self,
        session_id:  str,
        field_edits: dict[str, dict[str, Any]],
        server_host: Optional[str]  = None,
        server_port: Optional[int]  = None,
        frame_delay: float          = 0.0,
        direction:   Direction      = Direction.CLIENT_TO_SERVER,
        frame_selector: Optional[str] = None,
    ) -> ReplayResult:
        """
        Replay a session with field-level edits applied per message type.

        Instead of specifying raw replacement bytes per frame ID, you specify
        field values per message type.  The encoder decodes each frame,
        applies the matching edit dict, re-encodes, and sends.

        Args:
            session_id:   Session to replay.
            field_edits:  Dict of message_type_name → {field_name → new_value}.
                          Example::

                              {
                                  "LoginRequest": {
                                      "username": "admin2",
                                      "password": b"newpass!",
                                  }
                              }

            server_host:    Override target host.
            server_port:    Override target port.
            frame_delay:    Seconds between frames.
            direction:      Which direction's frames to replay.
            frame_selector: Selector string for specific frames.

        Returns:
            ReplayResult.

        Raises:
            RuntimeError: If no encoder is set.
        """
        from .protocol.parser.engine import DefinitionBasedEncoder

        if self._encoder is None or not isinstance(self._encoder, DefinitionBasedEncoder):
            raise RuntimeError(
                "replay_session_with_field_edits requires a DefinitionBasedEncoder. "
                "Call set_protocol_file() first."
            )

        decoder = self._decoder
        encoder = self._encoder

        # Pre-compute modified_frames: decode each frame, apply edits, re-encode
        frames = self.get_frames(session_id, direction)
        modified_frames: dict[str, bytes] = {}

        for frame in frames:
            msg = decoder.decode(frame)
            if msg.message_type in field_edits:
                try:
                    new_bytes = encoder.encode_with_edits(msg, field_edits[msg.message_type])
                    modified_frames[frame.id] = new_bytes
                except Exception as exc:
                    logger.warning(
                        "Could not encode frame %s (%s): %s — sending original",
                        frame.id[:8], msg.message_type, exc,
                    )

        return await self.replay_session(
            session_id=session_id,
            server_host=server_host,
            server_port=server_port,
            frame_delay=frame_delay,
            modified_frames=modified_frames or None,
            direction=direction,
            frame_selector=frame_selector,
        )

    # ------------------------------------------------------------------
    # Repeater: inject into existing session OR direct send
    # ------------------------------------------------------------------

    async def open_repeater_session(
        self,
        host: str,
        port: int,
        tls:  bool = False,
    ) -> str:
        """
        Open a persistent TCP connection to *host*:*port* for the Repeater.

        Registers the connection as a session in the session registry so it
        appears in the Logs tab and the "From session" dropdown.  The
        connection is kept alive between sends; it is closed (and the session
        marked CLOSED) automatically when the server drops the connection.

        Returns:
            The new session's ID.

        Raises:
            ConnectionError: if the connection cannot be established.
        """
        session = await self.replay_engine.open_repeater_session(host, port, tls)
        await self.event_bus.publish(
            SessionOpenedEvent(session=session.info)
        )
        return session.id

    async def send_on_repeater_session(
        self,
        session_id:       str,
        data:             bytes,
        receive_timeout:  Optional[float] = None,
        packet_callback:  Optional[Callable[[bytes], None]] = None,
    ) -> SendRecord:
        """
        Send *data* through an existing persistent repeater session.

        If the server closes the connection during the send the session is
        automatically marked CLOSED and a :class:`SessionClosedEvent` is
        fired so the Logs tab updates.

        Args:
            session_id:      ID returned by :meth:`open_repeater_session`.
            data:            Bytes to send.
            receive_timeout: Seconds to wait for a response.  Defaults to
                             the proxy's configured connect timeout.

        Returns:
            :class:`~protopoke.replay.models.SendRecord` with the response.
        """
        recv_timeout = receive_timeout if receive_timeout is not None else self.config.connect_timeout
        session_before = self.session_registry.get(session_id)
        was_active     = session_before is not None and session_before.is_active()

        record = await self.replay_engine.send_on_repeater_session(
            session_id=session_id,
            data=data,
            receive_timeout=recv_timeout,
            packet_callback=packet_callback,
        )

        # Add sent and received frames to the session so they appear in the Logs tab.
        session = self.session_registry.get(session_id)
        if session and record.sent_bytes:
            sent_frame = Frame.create(
                session_id=session_id,
                direction=Direction.CLIENT_TO_SERVER,
                raw_bytes=record.sent_bytes,
                sequence_number=len(session.frames),
                framer_name="repeater",
            )
            session.add_frame(sent_frame)
            await self.event_bus.publish(
                FrameCapturedEvent(frame=sent_frame, session=session.info)
            )
        for pkt in record.response_packets:
            session = self.session_registry.get(session_id)
            if session and pkt:
                recv_frame = Frame.create(
                    session_id=session_id,
                    direction=Direction.SERVER_TO_CLIENT,
                    raw_bytes=pkt,
                    sequence_number=len(session.frames),
                    framer_name="repeater",
                )
                session.add_frame(recv_frame)
                await self.event_bus.publish(
                    FrameCapturedEvent(frame=recv_frame, session=session.info)
                )

        # If the session transitioned to CLOSED during the send, fire the event
        session_after = self.session_registry.get(session_id)
        if was_active and session_after is not None and not session_after.is_active():
            await self.event_bus.publish(
                SessionClosedEvent(session=session_after.info)
            )

        return record

    async def inject_to_client(self, session_id: str, data: bytes) -> bool:
        """
        Write *data* directly into the client connection of an active session.

        The bytes arrive on the *same* TCP connection that the real server is
        using, so the client sees them as if they came from the server.  Useful
        for injecting server-to-client traffic during a sequencer run.

        Returns:
            ``True``  if the session was active and the write succeeded.
            ``False`` if the session has no active client writer (closed or
                      not found).
        """
        ok = await self.engine.inject_to_client(session_id, data)
        if ok:
            session = self.session_registry.get(session_id)
            if session and data:
                frame = Frame.create(
                    session_id=session_id,
                    direction=Direction.SERVER_TO_CLIENT,
                    raw_bytes=data,
                    sequence_number=len(session.frames),
                    framer_name="injected",
                )
                session.add_frame(frame)
                await self.event_bus.publish(
                    FrameCapturedEvent(frame=frame, session=session.info)
                )
        return ok

    async def inject_to_server(self, session_id: str, data: bytes) -> bool:
        """
        Write *data* directly into the upstream connection of an active session.

        The bytes arrive on the *same* TCP connection that the real client is
        using, so the server sees them as part of the established session.  The
        server's response (if any) flows back through the relay to the original
        client and is captured as a normal session frame.

        Returns:
            ``True``  if the session was active and the write succeeded.
            ``False`` if the session has no active upstream writer (closed or
                      not found) — callers should fall back to
                      :meth:`send_frame` in this case.
        """
        ok = await self.engine.inject_to_server(session_id, data)
        if ok:
            session = self.session_registry.get(session_id)
            if session and data:
                frame = Frame.create(
                    session_id=session_id,
                    direction=Direction.CLIENT_TO_SERVER,
                    raw_bytes=data,
                    sequence_number=len(session.frames),
                    framer_name="injected",
                )
                session.add_frame(frame)
                await self.event_bus.publish(
                    FrameCapturedEvent(frame=frame, session=session.info)
                )
        return ok

    async def send_frame(
        self,
        data:             bytes,
        host:             str,
        port:             int,
        tls:              bool           = False,
        connect_timeout:  Optional[float] = None,
        receive_timeout:  Optional[float] = None,
        packet_callback:  Optional[Callable[[bytes], None]] = None,
    ) -> SendRecord:
        """
        Send raw bytes to *host*:*port* and return a :class:`SendRecord`.

        Opens a direct TCP connection (bypassing the proxy listener),
        sends *data*, signals EOF, reads all response bytes, then closes
        the connection.  Suitable for the Repeater tab's one-shot send.

        Args:
            data:             Bytes to send.
            host:             Target hostname or IP address.
            port:             Target TCP port.
            tls:              Wrap the connection in TLS (no cert verification).
            connect_timeout:  Override the default connect timeout.
            receive_timeout:  Seconds to wait for the server response.  When
                              the deadline is reached the bytes received so far
                              are returned.  Defaults to the connect timeout.

        Returns:
            :class:`~protopoke.replay.models.SendRecord` with sent bytes,
            response bytes, success flag, and any error message.
        """
        # Create a one-shot session so the sent/received frames appear in the Logs tab.
        session = self.session_registry.create(
            client_host="repeater",
            client_port=0,
            server_host=host,
            server_port=port,
        )
        self.session_registry.mark_active(session.id)
        await self.event_bus.publish(SessionOpenedEvent(session=session.info))

        record = await self.replay_engine.send_frame(
            data=data,
            host=host,
            port=port,
            tls=tls,
            connect_timeout=connect_timeout,
            receive_timeout=receive_timeout,
            packet_callback=packet_callback,
        )

        if record.sent_bytes:
            sent_frame = Frame.create(
                session_id=session.id,
                direction=Direction.CLIENT_TO_SERVER,
                raw_bytes=record.sent_bytes,
                sequence_number=len(session.frames),
                framer_name="repeater",
            )
            session.add_frame(sent_frame)
            await self.event_bus.publish(
                FrameCapturedEvent(frame=sent_frame, session=session.info)
            )
        for pkt in record.response_packets:
            if pkt:
                recv_frame = Frame.create(
                    session_id=session.id,
                    direction=Direction.SERVER_TO_CLIENT,
                    raw_bytes=pkt,
                    sequence_number=len(session.frames),
                    framer_name="repeater",
                )
                session.add_frame(recv_frame)
                await self.event_bus.publish(
                    FrameCapturedEvent(frame=recv_frame, session=session.info)
                )

        self.session_registry.mark_closed(session.id)
        await self.event_bus.publish(SessionClosedEvent(session=session.info))

        return record

    # ------------------------------------------------------------------
    # Sequencer
    # ------------------------------------------------------------------

    async def run_sequence(
        self,
        seq:               SequencerSession,
        on_entry:          Optional[Callable[[HistoryEntry], None]] = None,
    ) -> None:
        """
        Execute a :class:`~protopoke.sequencer.models.SequencerSession`.

        Resolves ``##VAR##`` placeholders in each step, calls optional script
        hooks, sends packets, and records the flat history log.

        Connection mode is determined by ``seq.source_session_id``:

        - **Set**: inject each step's bytes into the named existing proxy
          session and capture ``SERVER_TO_CLIENT`` frames within the
          configured ``response_window``.
        - **Not set**: open (or reuse) a persistent TCP connection to
          ``seq.host:seq.port`` (with optional TLS) and use the repeater
          session mechanism.

        The configured ``sequencer_script`` (from :attr:`config`) is loaded
        once and its ``on_response`` / ``on_send`` hooks are called around
        each step.

        Args:
            seq:      The sequence to run.  Updated in-place (history, variables).
            on_entry: Optional callback invoked immediately after each
                      :class:`~protopoke.sequencer.models.HistoryEntry` is
                      created, allowing live UI updates.
        """
        import asyncio as _asyncio
        import time as _time

        # Load script once (if configured)
        script = None
        if self.config.sequencer_script:
            try:
                script = load_script(self.config.sequencer_script)
            except Exception as exc:
                logger.error(
                    "Failed to load sequencer script %s: %s",
                    self.config.sequencer_script, exc,
                )

        engine = SequencerEngine()

        # ------------------------------------------------------------------
        # Build the send_fn based on connection mode
        # ------------------------------------------------------------------

        if seq.source_session_id:
            # Session-linked: inject into an existing proxy session.
            # Direction routes the bytes to the appropriate side:
            #   client_to_server → inject_to_server (normal client traffic)
            #   server_to_client → inject_to_client (push data toward the client)
            _src_id = seq.source_session_id

            async def send_fn(data: bytes, direction: str = "client_to_server") -> list[bytes]:
                # Apply replace rules with sequencer scope before sending
                _dir = (
                    Direction.CLIENT_TO_SERVER
                    if direction == "client_to_server"
                    else Direction.SERVER_TO_CLIENT
                )
                data = self.rules_engine.apply_bytes(data, _dir, scope="sequencer")
                send_time = _time.time()
                if direction == "server_to_client":
                    ok = await self.inject_to_client(_src_id, data)
                    if not ok:
                        logger.warning(
                            "Sequencer: inject_to_client on %s failed", _src_id[:8]
                        )
                        return []
                    # Collect client-to-server frames that arrive after injection
                    await _asyncio.sleep(seq.response_window)
                    session = self.get_session(_src_id)
                    if not session:
                        return []
                    return [
                        f.raw_bytes
                        for f in session.frames
                        if f.direction is Direction.CLIENT_TO_SERVER
                        and f.timestamp >= send_time
                    ]
                else:
                    ok = await self.inject_to_server(_src_id, data)
                    if not ok:
                        logger.warning(
                            "Sequencer: inject_to_server on %s failed", _src_id[:8]
                        )
                        return []
                    await _asyncio.sleep(seq.response_window)
                    session = self.get_session(_src_id)
                    if not session:
                        return []
                    return [
                        f.raw_bytes
                        for f in session.frames
                        if f.direction is Direction.SERVER_TO_CLIENT
                        and f.timestamp >= send_time
                    ]

        else:
            # New / persistent connection via the repeater session pool.
            # server_to_client direction is not supported without an active proxy
            # session; log a warning and skip the response wait.
            _conn_id: list[Optional[str]] = [None]  # mutable cell

            async def send_fn(data: bytes, direction: str = "client_to_server") -> list[bytes]:  # type: ignore[misc]
                if direction == "server_to_client":
                    logger.warning(
                        "Sequencer: server_to_client step requires a linked proxy "
                        "session (set Session ID in the run bar); skipping step."
                    )
                    return []

                # Apply replace rules with sequencer scope before sending
                _dir = Direction.CLIENT_TO_SERVER
                data = self.rules_engine.apply_bytes(data, _dir, scope="sequencer")

                # Verify the persistent connection is still alive
                if _conn_id[0]:
                    session = self.get_session(_conn_id[0])
                    if not (session and session.is_active()):
                        _conn_id[0] = None

                # Open a new connection if needed
                if _conn_id[0] is None:
                    try:
                        _conn_id[0] = await self.open_repeater_session(
                            seq.host, seq.port, seq.tls
                        )
                    except ConnectionError as exc:
                        logger.error("Sequencer: cannot connect: %s", exc)
                        return []

                record = await self.send_on_repeater_session(
                    session_id=_conn_id[0],
                    data=data,
                    receive_timeout=seq.response_window,
                )

                # If server closed the connection, clear the cell
                if _conn_id[0]:
                    s = self.get_session(_conn_id[0])
                    if s and not s.is_active():
                        _conn_id[0] = None

                return record.response_packets

        await engine.run(seq, send_fn=send_fn, script=script, on_entry=on_entry)

    # ------------------------------------------------------------------
    # Replace rules management
    # ------------------------------------------------------------------

    def add_replace_rule(self, rule: ReplaceRule) -> None:
        """Append a replace rule to the active RulesEngine."""
        self.rules_engine.add_rule(rule)

    def remove_replace_rule(self, rule_id: str) -> bool:
        """Remove a replace rule by ID. Returns ``True`` if found."""
        return self.rules_engine.remove_rule(rule_id)

    def list_replace_rules(self) -> list[ReplaceRule]:
        """Snapshot of active replace rules (ordered)."""
        return self.rules_engine.rules

    # ------------------------------------------------------------------
    # Intercept rules management
    # ------------------------------------------------------------------

    def add_intercept_rule(self, rule: InterceptRule) -> None:
        """Append an intercept rule to the active InterceptFilter."""
        self.intercept_filter.add_rule(rule)

    def remove_intercept_rule(self, rule_id: str) -> bool:
        """Remove an intercept rule by ID. Returns ``True`` if found."""
        return self.intercept_filter.remove_rule(rule_id)

    def list_intercept_rules(self) -> list[InterceptRule]:
        """Snapshot of active intercept rules (ordered)."""
        return self.intercept_filter.rules

    @property
    def intercept_direction_filter(self) -> "Optional[Direction]":
        """Direction filter on the intercept controller, or ``None``."""
        return self._intercept_controller.direction_filter

    @intercept_direction_filter.setter
    def intercept_direction_filter(self, value: "Optional[Direction]") -> None:
        """Set the direction filter on the intercept controller."""
        self._intercept_controller.direction_filter = value

    @property
    def intercept_session_filter(self) -> "Optional[set[str]]":
        """Session ID filter on the intercept controller, or ``None``."""
        return self._intercept_controller.session_filter

    @intercept_session_filter.setter
    def intercept_session_filter(self, value: "Optional[set[str]]") -> None:
        """Set the session ID filter on the intercept controller."""
        self._intercept_controller.session_filter = value

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

    # ------------------------------------------------------------------
    # Fuzzing
    # ------------------------------------------------------------------

    def _get_fuzzer_engine(self) -> FuzzerEngine:
        """Return (lazily constructing) the FuzzerEngine for this API instance."""
        if self._fuzzer_engine is None:
            self._fuzzer_engine = FuzzerEngine(
                replay_engine=self.replay_engine,
                session_registry=self.session_registry,
                decoder=self._decoder,
            )
        return self._fuzzer_engine

    async def fuzz_session(
        self,
        session_id:       str,
        mutators:         list[FrameMutator],
        iterations:       int            = 50,
        frame_selector:   Optional[str]  = None,
        stop_on_crash:    bool           = True,
        server_host:      Optional[str]  = None,
        server_port:      Optional[int]  = None,
        response_timeout: float          = 10.0,
        on_result:        Optional[Callable[[FuzzResult], None]] = None,
    ) -> FuzzCampaign:
        """
        Fuzz a captured session by replaying it with mutations applied.

        For each iteration, one frame from the session is selected and
        mutated by one of the provided mutators before being sent.  The
        engine cycles through frames and mutators round-robin, so each
        mutator gets an equal number of turns.

        A baseline replay is performed first so that response size anomalies
        can be detected automatically.

        Args:
            session_id:       Session to use as the template (must be captured).
            mutators:         List of FrameMutator instances to use.
            iterations:       Number of mutations to send (default: 50).
            frame_selector:   Which frames to fuzz — same syntax as replay_session().
                              None = all client-to-server frames.
            stop_on_crash:    Stop the campaign on first connection reset.
            server_host:      Override target host (default: original session server).
            server_port:      Override target port.
            response_timeout: Seconds to wait for a server response per iteration.
            on_result:        Optional callback called after each FuzzResult.

        Returns:
            FuzzCampaign with all results populated.
        """
        campaign = FuzzCampaign.create(
            session_id=session_id,
            mutators=mutators,
            iterations=iterations,
            frame_selector=frame_selector,
            stop_on_crash=stop_on_crash,
        )
        engine = self._get_fuzzer_engine()
        # Sync the decoder in case set_protocol was called after construction
        engine._decoder = self._decoder
        return await engine.run_campaign(
            campaign=campaign,
            mutators=mutators,
            server_host=server_host,
            server_port=server_port,
            response_timeout=response_timeout,
            on_result=on_result,
        )
