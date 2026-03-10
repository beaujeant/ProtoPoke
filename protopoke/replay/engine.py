"""
Replay engine.

Replay is a first-class concern in this architecture — not an afterthought.
The ability to record a session and send it again (to the same or a different
server, with optional modifications) is essential for security testing:

    - Confirming a finding is reproducible
    - Testing a fix (did the server behavior change?)
    - Fuzzing: replay with modified fields
    - Regression testing: compare responses between server versions

Design:
    ReplayEngine replays frames from a captured Session to a target server,
    captures the server's responses, and returns a new Session containing both
    the sent frames and the received responses.

    The new session is registered in the SessionRegistry, so it appears in
    the API's session list like any other session. It can itself be replayed,
    compared, or have its frames inspected.

Frame selection:
    By default all client→server frames are replayed in sequence order.

    direction:      Which direction's frames to source. Defaults to
                    CLIENT_TO_SERVER. Set to SERVER_TO_CLIENT to replay
                    what the server sent (useful for testing client-side
                    parsing or unusual server-replay scenarios).

    frame_selector: A selector string that picks specific frames by sequence
                    number within the chosen direction. Syntax:

                        "5"          — only frame with sequence_number 5
                        "3-13"       — frames 3 through 13 inclusive
                        "3,4,7"      — frames 3, 4 and 7
                        "3,5,7-9,11" — frames 3, 5, 7, 8, 9 and 11

                    Sequence numbers that don't exist in the captured session
                    are silently ignored. If the selector matches no frames,
                    replay returns a failure result.

Limitations of the current implementation:
    - No timing: frames are sent as fast as the server accepts them.
      (frame_delay parameter adds a uniform inter-frame delay.)
    - No stateful replay: if the protocol requires a handshake that changes
      per session (e.g. a nonce), the replayed bytes may be rejected.
    - No mid-replay interception: replayed frames are not passed through the
      intercept controller. (Future: make this optional.)

Future improvements:
    - Stateful replay: allow the caller to supply a transformer function that
      adapts frames based on server responses (for protocols with session tokens).
    - Differential replay: two engines, compare responses frame-by-frame.
    - Timed replay: honor original inter-frame delays.
    - Intercepted replay: route replayed frames through the intercept controller.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

from ..models import Direction, Frame, SessionInfo
from ..core.session import Session, SessionRegistry
from ..framing import create_framer
from .models import RepeaterRequest, SendRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Frame selector parser
# ---------------------------------------------------------------------------

def parse_frame_selector(selector: str) -> set[int]:
    """
    Parse a frame selector string into a set of sequence numbers.

    Syntax (whitespace around separators is ignored):
        "5"          → {5}
        "3-13"       → {3, 4, 5, …, 13}
        "3,4,7"      → {3, 4, 7}
        "3,5,7-9,11" → {3, 5, 7, 8, 9, 11}

    Raises:
        ValueError: if the selector string is malformed or a range is
                    specified in reverse order (e.g. "9-3").
    """
    result: set[int] = set()

    for token in selector.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(
                    f"Invalid range '{token}': expected 'start-end'"
                )
            start_s, end_s = parts[0].strip(), parts[1].strip()
            if not start_s.isdigit() or not end_s.isdigit():
                raise ValueError(
                    f"Invalid range '{token}': start and end must be non-negative integers"
                )
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(
                    f"Invalid range '{token}': start ({start}) is greater than end ({end})"
                )
            result.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(
                    f"Invalid sequence number '{token}': must be a non-negative integer"
                )
            result.add(int(token))

    return result


# ---------------------------------------------------------------------------
# ReplayResult
# ---------------------------------------------------------------------------

@dataclass
class ReplayResult:
    """
    The outcome of replaying a session.

    Attributes:
        original_session_id: ID of the session that was replayed.
        replayed_session:    New session containing sent frames + server responses.
        success:             True if the replay completed without errors.
        error:               Error message if success is False.
        started_at:          When the replay began.
        completed_at:        When the replay finished (or None if still running).
    """
    original_session_id: str
    replayed_session:    Session
    success:             bool
    error:               Optional[str] = None
    started_at:          float = field(default_factory=time.time)
    completed_at:        Optional[float] = None

    def frames_sent(self) -> list[Frame]:
        """Frames that were sent to the server during replay."""
        return [
            f for f in self.replayed_session.frames
            if f.direction is Direction.CLIENT_TO_SERVER
        ]

    def frames_received(self) -> list[Frame]:
        """Frames received from the server during replay."""
        return [
            f for f in self.replayed_session.frames
            if f.direction is Direction.SERVER_TO_CLIENT
        ]

    def total_bytes_sent(self) -> int:
        return sum(len(f.raw_bytes) for f in self.frames_sent())

    def total_bytes_received(self) -> int:
        return sum(len(f.raw_bytes) for f in self.frames_received())

    # Backward-compatible aliases
    def client_frames_sent(self) -> list[Frame]:
        return self.frames_sent()

    def server_frames_received(self) -> list[Frame]:
        return self.frames_received()

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict for MCP tool responses."""
        return {
            "original_session_id":  self.original_session_id,
            "replayed_session_id":  self.replayed_session.id,
            "success":              self.success,
            "error":                self.error,
            "started_at":           self.started_at,
            "completed_at":         self.completed_at,
            "frames_sent":          len(self.frames_sent()),
            "frames_received":      len(self.frames_received()),
            "total_bytes_sent":     self.total_bytes_sent(),
            "total_bytes_received": self.total_bytes_received(),
        }


# ---------------------------------------------------------------------------
# ReplayEngine
# ---------------------------------------------------------------------------

class ReplayEngine:
    """
    Replays captured TCP sessions against a target server.

    Usage:
        engine = ReplayEngine(session_registry)

        # Replay all client→server frames (default)
        result = await engine.replay_session(session_id="...")

        # Replay only frames 3 through 7
        result = await engine.replay_session(
            session_id="...",
            frame_selector="3-7",
        )

        # Replay only the server→client direction
        result = await engine.replay_session(
            session_id="...",
            direction=Direction.SERVER_TO_CLIENT,
        )

        if result.success:
            for frame in result.frames_received():
                print(frame.raw_bytes)
    """

    def __init__(
        self,
        session_registry: SessionRegistry,
        connect_timeout:  float = 10.0,
        framer_name:      str   = "raw",
        framer_kwargs:    dict  = None,
    ) -> None:
        self._session_registry = session_registry
        self._connect_timeout  = connect_timeout
        self._framer_name      = framer_name
        self._framer_kwargs    = framer_kwargs or {}
        # Persistent connections created by the Repeater for custom host:port sends.
        # Maps session_id → (reader, writer, tls_flag)
        self._open_connections: dict[
            str,
            tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]
        ] = {}

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
            session_id:      ID of the session to replay. Must exist in registry.
            server_host:     Override target host (default: same as original session).
            server_port:     Override target port (default: same as original session).
            frame_delay:     Seconds to wait between sending frames. 0 = no delay.
            modified_frames: Dict of frame_id → replacement bytes. Frames not in
                             the dict are sent with their original bytes.
            direction:       Which direction's frames to source for replay.
                             Default: CLIENT_TO_SERVER (what the client sent).
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
        original = self._session_registry.get(session_id)
        if not original:
            stub_info = SessionInfo.create("replay", 0, server_host or "", server_port or 0)
            stub = Session(stub_info)
            return ReplayResult(
                original_session_id=session_id,
                replayed_session=stub,
                success=False,
                error=f"Session '{session_id}' not found in registry",
                completed_at=time.time(),
            )

        target_host = server_host or original.info.server_host
        target_port = server_port or original.info.server_port

        # Parse the selector into a set of sequence numbers (or None = all)
        selected_seqs: Optional[set[int]] = None
        if frame_selector is not None:
            try:
                selected_seqs = parse_frame_selector(frame_selector)
            except ValueError as exc:
                stub_info = SessionInfo.create("replay", 0, target_host, target_port)
                stub = Session(stub_info)
                return ReplayResult(
                    original_session_id=session_id,
                    replayed_session=stub,
                    success=False,
                    error=f"Invalid frame_selector: {exc}",
                    completed_at=time.time(),
                )

        # Collect frames for the requested direction, sorted by sequence number
        source_frames = sorted(
            (f for f in original.frames if f.direction is direction),
            key=lambda f: f.sequence_number,
        )

        # Apply the selector if provided
        if selected_seqs is not None:
            source_frames = [f for f in source_frames if f.sequence_number in selected_seqs]

        if not source_frames:
            dir_label = direction.value
            selector_label = f" matching selector '{frame_selector}'" if frame_selector else ""
            stub_info = SessionInfo.create("replay", 0, target_host, target_port)
            stub = Session(stub_info)
            return ReplayResult(
                original_session_id=session_id,
                replayed_session=stub,
                success=False,
                error=f"No {dir_label} frames{selector_label} to replay",
                completed_at=time.time(),
            )

        # Register a new session for this replay run
        replayed = self._session_registry.create(
            client_host="replay",
            client_port=0,
            server_host=target_host,
            server_port=target_port,
        )

        logger.info(
            "Replaying session %s → new session %s to %s:%d "
            "(%d %s frames%s)",
            session_id, replayed.id, target_host, target_port,
            len(source_frames), direction.value,
            f" [selector={frame_selector!r}]" if frame_selector else "",
        )

        result = ReplayResult(
            original_session_id=session_id,
            replayed_session=replayed,
            success=False,
        )

        try:
            await self._execute_replay(
                replayed_session=replayed,
                source_frames=source_frames,
                target_host=target_host,
                target_port=target_port,
                frame_delay=frame_delay,
                modified_frames=modified_frames or {},
                result=result,
            )
        except Exception as exc:
            logger.error("Replay failed: %s", exc, exc_info=True)
            result.error = str(exc)
            result.success = False
        finally:
            result.completed_at = time.time()
            self._session_registry.mark_closed(replayed.id)

        return result

    async def _execute_replay(
        self,
        replayed_session: Session,
        source_frames:    list[Frame],
        target_host:      str,
        target_port:      int,
        frame_delay:      float,
        modified_frames:  dict[str, bytes],
        result:           ReplayResult,
    ) -> None:
        """Internal: connect to the server, send frames, capture responses."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=self._connect_timeout,
            )
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"Timeout connecting to {target_host}:{target_port}"
            )
        except OSError as exc:
            raise ConnectionError(f"Connection failed: {exc}")

        self._session_registry.mark_active(replayed_session.id)

        # Framer for server responses
        server_framer = create_framer(
            self._framer_name,
            session_id=replayed_session.id,
            direction=Direction.SERVER_TO_CLIENT,
            **self._framer_kwargs,
        )

        try:
            for original_frame in source_frames:
                data = modified_frames.get(original_frame.id, original_frame.raw_bytes)

                sent_frame = Frame.create(
                    session_id=replayed_session.id,
                    direction=Direction.CLIENT_TO_SERVER,
                    raw_bytes=data,
                    sequence_number=original_frame.sequence_number,
                    framer_name="replay",
                )
                replayed_session.add_frame(sent_frame)

                writer.write(data)
                await writer.drain()

                logger.debug(
                    "Sent frame seq=%d len=%d to %s:%d",
                    original_frame.sequence_number, len(data),
                    target_host, target_port,
                )

                if frame_delay > 0:
                    await asyncio.sleep(frame_delay)

            # Signal EOF to the server
            writer.write_eof()
            await writer.drain()

            # Read all server responses
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                for recv_frame in server_framer.feed(data):
                    replayed_session.add_frame(recv_frame)

            for recv_frame in server_framer.flush():
                replayed_session.add_frame(recv_frame)

            result.success = True
            logger.info(
                "Replay complete: sent=%d frames (%d bytes), received=%d frames (%d bytes)",
                len(result.frames_sent()), result.total_bytes_sent(),
                len(result.frames_received()), result.total_bytes_received(),
            )

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Persistent repeater sessions (custom host:port)
    # ------------------------------------------------------------------

    async def open_repeater_session(
        self,
        host: str,
        port: int,
        tls:  bool = False,
    ) -> "Session":
        """
        Open a persistent TCP connection to *host*:*port* and register it as a
        session in the registry.

        The connection is kept alive between sends (no EOF signalled).  Call
        :meth:`send_on_repeater_session` to send data through it.  The session
        is automatically closed and removed when the server drops the connection.

        Returns:
            The newly created :class:`Session` (state=ACTIVE).

        Raises:
            ConnectionError: if the connection cannot be established.
        """
        ssl_ctx: Optional[ssl.SSLContext] = None
        if tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port,
                    ssl=ssl_ctx,
                    server_hostname=host if ssl_ctx else None,
                ),
                timeout=self._connect_timeout,
            )
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"Timeout connecting to {host}:{port} ({self._connect_timeout}s)"
            )
        except OSError as exc:
            raise ConnectionError(f"Connection failed to {host}:{port}: {exc}") from exc

        session = self._session_registry.create(
            client_host="repeater",
            client_port=0,
            server_host=host,
            server_port=port,
        )
        self._session_registry.mark_active(session.id)
        self._open_connections[session.id] = (reader, writer, tls)

        logger.info(
            "Repeater session opened: %s → %s:%d (tls=%s)",
            session.id[:8], host, port, tls,
        )
        return session

    async def send_on_repeater_session(
        self,
        session_id:      str,
        data:            bytes,
        receive_timeout: float = 10.0,
    ) -> SendRecord:
        """
        Send *data* through an existing persistent repeater session and read
        the server's response.

        Unlike :meth:`send_frame`, this method does **not** signal EOF after
        sending, so the TCP connection stays alive for subsequent sends.

        If the server closes the connection during the send, the session is
        marked closed, removed from the pool, and the partial response (if
        any) is returned as a successful record so the operator can see what
        came back before the close.

        Args:
            session_id:      ID of the session opened via :meth:`open_repeater_session`.
            data:            Bytes to send.
            receive_timeout: Seconds to wait for the server's response.
                             On timeout the bytes received so far are returned
                             and the connection stays open.

        Returns:
            A :class:`SendRecord` with the sent bytes and received response.
        """
        conn = self._open_connections.get(session_id)
        session = self._session_registry.get(session_id)

        if not conn or not session:
            return SendRecord.create(
                sent_bytes=data,
                received_bytes=b"",
                host="",
                port=0,
                tls=False,
                success=False,
                error=f"Repeater session {session_id[:8]} not found or not open",
            )

        reader, writer, tls = conn
        host = session.info.server_host
        port = session.info.server_port

        received      = bytearray()
        server_closed = False

        try:
            writer.write(data)   # No write_eof() — keep connection alive
            await writer.drain()

            async def _read_response() -> None:
                nonlocal server_closed
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        server_closed = True
                        break
                    received.extend(chunk)

            try:
                await asyncio.wait_for(_read_response(), timeout=receive_timeout)
            except asyncio.TimeoutError:
                pass  # Normal — connection is alive, no more data in the window

        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            server_closed = True
            return SendRecord.create(
                sent_bytes=data,
                received_bytes=bytes(received),
                host=host,
                port=port,
                tls=tls,
                success=False,
                error=f"I/O error: {exc}",
            )
        finally:
            if server_closed:
                self._open_connections.pop(session_id, None)
                self._session_registry.mark_closed(session_id)
                logger.info(
                    "Repeater session %s closed by server after send", session_id[:8]
                )

        logger.info(
            "send_on_repeater_session %s: sent=%d bytes, received=%d bytes",
            session_id[:8], len(data), len(received),
        )
        return SendRecord.create(
            sent_bytes=data,
            received_bytes=bytes(received),
            host=host,
            port=port,
            tls=tls,
            success=True,
        )

    async def send_frame(
        self,
        data:             bytes,
        host:             str,
        port:             int,
        tls:              bool           = False,
        connect_timeout:  Optional[float] = None,
        receive_timeout:  Optional[float] = None,
    ) -> SendRecord:
        """
        Send raw bytes to *host*:*port* and read all response bytes.

        Opens a new direct TCP connection (bypassing the proxy listener),
        sends *data*, signals EOF, reads the full response, then closes
        the connection.  Suitable for the Repeater's one-shot send action.

        Args:
            data:             Bytes to send.
            host:             Target hostname or IP address.
            port:             Target TCP port.
            tls:              Wrap the connection in TLS (no cert verification).
            connect_timeout:  Override the engine's default connect timeout.
            receive_timeout:  Seconds to wait for the server to finish sending
                              its response.  When the deadline is reached the
                              bytes received so far are returned as a successful
                              record (the server simply kept the connection open).
                              Defaults to the same value as *connect_timeout*.

        Returns:
            A ``SendRecord`` capturing the sent bytes, response bytes,
            success flag, and error message (if any).
        """
        timeout = connect_timeout if connect_timeout is not None else self._connect_timeout
        recv_timeout = receive_timeout if receive_timeout is not None else timeout
        ssl_ctx: Optional[ssl.SSLContext] = None
        if tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port,
                    ssl=ssl_ctx,
                    server_hostname=host if ssl_ctx else None,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return SendRecord.create(
                sent_bytes=data,
                received_bytes=b"",
                host=host,
                port=port,
                tls=tls,
                success=False,
                error=f"Connection timeout ({timeout}s)",
            )
        except OSError as exc:
            return SendRecord.create(
                sent_bytes=data,
                received_bytes=b"",
                host=host,
                port=port,
                tls=tls,
                success=False,
                error=f"Connection failed: {exc}",
            )

        received = bytearray()
        try:
            writer.write(data)
            if writer.can_write_eof():
                writer.write_eof()
            await writer.drain()

            async def _read_all() -> None:
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    received.extend(chunk)

            try:
                await asyncio.wait_for(_read_all(), timeout=recv_timeout)
            except asyncio.TimeoutError:
                logger.debug(
                    "send_frame: receive timeout (%ss) — returning %d bytes received so far",
                    recv_timeout, len(received),
                )

        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            return SendRecord.create(
                sent_bytes=data,
                received_bytes=bytes(received),
                host=host,
                port=port,
                tls=tls,
                success=False,
                error=f"I/O error: {exc}",
            )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        logger.info(
            "send_frame: sent=%d bytes, received=%d bytes to %s:%d",
            len(data), len(received), host, port,
        )
        return SendRecord.create(
            sent_bytes=data,
            received_bytes=bytes(received),
            host=host,
            port=port,
            tls=tls,
            success=True,
        )
