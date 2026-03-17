"""
Forge engine — session replay, persistent send sessions, and playbook execution.

ForgeEngine
-----------
Replays captured TCP sessions against a target server. Used by the fuzzer
and any code that needs direct session replay.

PlaybookEngine
--------------
Executes an ordered list of PlaybookFrames (a Playbook) over a transport
send function, resolving {{VAR}} placeholders, emitting TrafficEntry objects,
and returning a completed PlaybookRun.

SendResult
----------
Lightweight return type for individual send operations. Contains the sent
bytes, received bytes, response packets, and success / error information.

parse_frame_selector
--------------------
Utility for parsing frame selector strings used by the fuzzer
(e.g. "5", "3-13", "3,5,7-9,11").
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional

from ..models import Direction, Frame, SessionInfo
from ..core.session import Session, SessionRegistry
from ..framing import create_framer
from .models import Playbook, PlaybookRun, TrafficEntry
from .variables import resolve_hex

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Frame selector parser  (used by FuzzerEngine)
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
# SendResult  (returned by per-send operations on ForgeEngine)
# ---------------------------------------------------------------------------

@dataclass
class SendResult:
    """
    The outcome of a single send operation.

    Attributes:
        sent_bytes:       Bytes that were sent.
        received_bytes:   All bytes received (concatenated).
        response_packets: Individual framed chunks received from the server.
        host:             Target host.
        port:             Target port.
        tls:              Whether TLS was used.
        success:          False if a connection or I/O error occurred.
        error:            Error message when success is False.
    """
    sent_bytes:       bytes
    received_bytes:   bytes
    response_packets: list[bytes]
    host:             str
    port:             int
    tls:              bool           = False
    success:          bool           = True
    error:            Optional[str]  = None

    @classmethod
    def failure(
        cls,
        sent_bytes: bytes,
        host: str,
        port: int,
        tls: bool,
        error: str,
        received_bytes: bytes = b"",
        response_packets: Optional[list[bytes]] = None,
    ) -> "SendResult":
        return cls(
            sent_bytes=sent_bytes,
            received_bytes=received_bytes,
            response_packets=response_packets or [],
            host=host,
            port=port,
            tls=tls,
            success=False,
            error=error,
        )


# ---------------------------------------------------------------------------
# ForgeResult  (returned by session replay operations)
# ---------------------------------------------------------------------------

@dataclass
class ForgeResult:
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
        return [
            f for f in self.replayed_session.frames
            if f.direction is Direction.CLIENT_TO_SERVER
        ]

    def frames_received(self) -> list[Frame]:
        return [
            f for f in self.replayed_session.frames
            if f.direction is Direction.SERVER_TO_CLIENT
        ]

    def total_bytes_sent(self) -> int:
        return sum(len(f.raw_bytes) for f in self.frames_sent())

    def total_bytes_received(self) -> int:
        return sum(len(f.raw_bytes) for f in self.frames_received())

    def to_dict(self) -> dict:
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
# ForgeEngine  (used by FuzzerEngine and API replay methods)
# ---------------------------------------------------------------------------

class ForgeEngine:
    """
    Replays captured TCP sessions against a target server, and manages
    persistent forge sessions for repeated sends.

    Used by FuzzerEngine and the ProxyAPI replay methods.
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
        # Persistent connections: session_id → (writer, tls, reader_queue, reader_task)
        self._open_connections: dict[
            str,
            tuple[asyncio.StreamWriter, bool, asyncio.Queue, asyncio.Task]
        ] = {}

    def update_framer(self, framer_name: str, framer_kwargs: dict) -> None:
        """Update the framer used for all future forge and playbook operations."""
        self._framer_name   = framer_name
        self._framer_kwargs = framer_kwargs

    async def forge_session(
        self,
        session_id:      str,
        server_host:     Optional[str]              = None,
        server_port:     Optional[int]              = None,
        frame_delay:     float                      = 0.0,
        modified_frames: Optional[dict[str, bytes]] = None,
        direction:       Direction                  = Direction.CLIENT_TO_SERVER,
        frame_selector:  Optional[str]              = None,
    ) -> ForgeResult:
        """Replay a captured session to a target server."""
        original = self._session_registry.get(session_id)
        if not original:
            stub_info = SessionInfo.create("replay", 0, server_host or "", server_port or 0)
            stub = Session(stub_info)
            return ForgeResult(
                original_session_id=session_id,
                replayed_session=stub,
                success=False,
                error=f"Session '{session_id}' not found in registry",
                completed_at=time.time(),
            )

        target_host = server_host or original.info.server_host
        target_port = server_port or original.info.server_port

        selected_seqs: Optional[set[int]] = None
        if frame_selector is not None:
            try:
                selected_seqs = parse_frame_selector(frame_selector)
            except ValueError as exc:
                stub_info = SessionInfo.create("replay", 0, target_host, target_port)
                stub = Session(stub_info)
                return ForgeResult(
                    original_session_id=session_id,
                    replayed_session=stub,
                    success=False,
                    error=f"Invalid frame_selector: {exc}",
                    completed_at=time.time(),
                )

        source_frames = sorted(
            (f for f in original.frames if f.direction is direction),
            key=lambda f: f.sequence_number,
        )
        if selected_seqs is not None:
            source_frames = [f for f in source_frames if f.sequence_number in selected_seqs]

        if not source_frames:
            dir_label = direction.value
            selector_label = f" matching selector '{frame_selector}'" if frame_selector else ""
            stub_info = SessionInfo.create("replay", 0, target_host, target_port)
            stub = Session(stub_info)
            return ForgeResult(
                original_session_id=session_id,
                replayed_session=stub,
                success=False,
                error=f"No {dir_label} frames{selector_label} to replay",
                completed_at=time.time(),
            )

        replayed = self._session_registry.create(
            client_host="replay",
            client_port=0,
            server_host=target_host,
            server_port=target_port,
        )

        result = ForgeResult(
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
        result:           ForgeResult,
    ) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=self._connect_timeout,
            )
        except asyncio.TimeoutError:
            raise ConnectionError(f"Timeout connecting to {target_host}:{target_port}")
        except OSError as exc:
            raise ConnectionError(f"Connection failed: {exc}")

        self._session_registry.mark_active(replayed_session.id)

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
                if frame_delay > 0:
                    await asyncio.sleep(frame_delay)

            writer.write_eof()
            await writer.drain()

            while True:
                data = await reader.read(4096)
                if not data:
                    break
                for recv_frame in server_framer.feed(data):
                    replayed_session.add_frame(recv_frame)

            for recv_frame in server_framer.flush():
                replayed_session.add_frame(recv_frame)

            result.success = True
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Persistent forge sessions (used by PlaybookEngine via API)
    # ------------------------------------------------------------------

    async def open_forge_session(
        self,
        host: str,
        port: int,
        tls:  bool = False,
    ) -> "Session":
        """
        Open a persistent TCP connection and register it as a session.
        The connection is kept alive between sends.

        Returns:
            The newly created Session (state=ACTIVE).

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
            client_host="forge",
            client_port=0,
            server_host=host,
            server_port=port,
        )
        self._session_registry.mark_active(session.id)

        reader_queue: asyncio.Queue = asyncio.Queue()
        reader_task = asyncio.get_event_loop().create_task(
            self._background_reader(reader, reader_queue),
            name=f"forge-reader-{session.id[:8]}",
        )
        self._open_connections[session.id] = (writer, tls, reader_queue, reader_task)
        return session

    async def _background_reader(
        self,
        reader: asyncio.StreamReader,
        queue:  asyncio.Queue,
    ) -> None:
        """Background task — sole consumer of *reader*. Puts b"" on EOF."""
        try:
            while True:
                chunk = await reader.read(4096)
                await queue.put(chunk)
                if not chunk:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            await queue.put(exc)

    async def send_on_forge_session(
        self,
        session_id:       str,
        data:             bytes,
        receive_timeout:  float = 10.0,
        packet_callback:  Optional[Callable[[bytes], None]] = None,
    ) -> SendResult:
        """
        Send *data* through a persistent forge session and collect the response.

        Does not signal EOF — the TCP connection stays alive for subsequent sends.

        Returns:
            A SendResult with the sent bytes and received response.
        """
        conn    = self._open_connections.get(session_id)
        session = self._session_registry.get(session_id)

        if not conn or not session:
            return SendResult.failure(
                sent_bytes=data, host="", port=0, tls=False,
                error=f"Forge session {session_id[:8]} not found or not open",
            )

        writer, tls, queue, reader_task = conn
        host = session.info.server_host
        port = session.info.server_port

        response_framer = create_framer(
            self._framer_name,
            session_id=session_id,
            direction=Direction.SERVER_TO_CLIENT,
            **self._framer_kwargs,
        )

        received:          bytearray      = bytearray()
        received_packets:  list[bytes]    = []
        server_closed:     bool           = False
        io_error: Optional[Exception]     = None

        try:
            writer.write(data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            io_error      = exc
            server_closed = True

        if not server_closed:
            deadline = asyncio.get_event_loop().time() + receive_timeout
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if isinstance(chunk, Exception):
                    io_error      = chunk
                    server_closed = True
                    break
                if not chunk:
                    server_closed = True
                    break
                received.extend(chunk)
                for frame in response_framer.feed(chunk):
                    received_packets.append(frame.raw_bytes)
                    if packet_callback is not None:
                        packet_callback(frame.raw_bytes)

        for frame in response_framer.flush():
            if frame.raw_bytes:
                received_packets.append(frame.raw_bytes)
                if packet_callback is not None:
                    packet_callback(frame.raw_bytes)

        if server_closed:
            reader_task.cancel()
            self._open_connections.pop(session_id, None)
            self._session_registry.mark_closed(session_id)
            if io_error:
                return SendResult.failure(
                    sent_bytes=data,
                    received_bytes=bytes(received),
                    response_packets=received_packets,
                    host=host, port=port, tls=tls,
                    error=f"I/O error: {io_error}",
                )

        return SendResult(
            sent_bytes=data,
            received_bytes=bytes(received),
            response_packets=received_packets,
            host=host, port=port, tls=tls,
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
        packet_callback:  Optional[Callable[[bytes], None]] = None,
    ) -> SendResult:
        """
        One-shot send: open connection, send data, signal EOF, read all response, close.
        """
        timeout      = connect_timeout if connect_timeout is not None else self._connect_timeout
        recv_timeout = receive_timeout if receive_timeout is not None else timeout
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
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return SendResult.failure(
                sent_bytes=data, host=host, port=port, tls=tls,
                error=f"Connection timeout ({timeout}s)",
            )
        except OSError as exc:
            return SendResult.failure(
                sent_bytes=data, host=host, port=port, tls=tls,
                error=f"Connection failed: {exc}",
            )

        oneshot_id = f"oneshot-{host}-{port}"
        response_framer = create_framer(
            self._framer_name,
            session_id=oneshot_id,
            direction=Direction.SERVER_TO_CLIENT,
            **self._framer_kwargs,
        )

        received:         bytearray   = bytearray()
        received_packets: list[bytes] = []
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
                    for frame in response_framer.feed(chunk):
                        received_packets.append(frame.raw_bytes)
                        if packet_callback is not None:
                            packet_callback(frame.raw_bytes)

            try:
                await asyncio.wait_for(_read_all(), timeout=recv_timeout)
            except asyncio.TimeoutError:
                pass

        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            for frame in response_framer.flush():
                if frame.raw_bytes:
                    received_packets.append(frame.raw_bytes)
                    if packet_callback is not None:
                        packet_callback(frame.raw_bytes)
            return SendResult.failure(
                sent_bytes=data,
                received_bytes=bytes(received),
                response_packets=received_packets,
                host=host, port=port, tls=tls,
                error=f"I/O error: {exc}",
            )
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        for frame in response_framer.flush():
            if frame.raw_bytes:
                received_packets.append(frame.raw_bytes)
                if packet_callback is not None:
                    packet_callback(frame.raw_bytes)

        return SendResult(
            sent_bytes=data,
            received_bytes=bytes(received),
            response_packets=received_packets,
            host=host, port=port, tls=tls,
            success=True,
        )


# ---------------------------------------------------------------------------
# PlaybookEngine
# ---------------------------------------------------------------------------

# Type alias for the send function passed into PlaybookEngine.run()
SendFn = Callable[[bytes, str], Awaitable[List[bytes]]]


class PlaybookEngine:
    """
    Executes a Playbook: sends each frame in order, collecting traffic.

    The engine is stateless — create one instance and call run() for each
    playbook execution. The returned PlaybookRun is NOT automatically appended
    to playbook.runs; the caller decides whether to persist it (so partial runs
    from interrupted executions are not silently stored).

    Variable resolution uses the same {{VAR}} syntax as the old sequence engine.
    Playbook-local variables in playbook.variables override global_variables.
    """

    async def run(
        self,
        playbook:         Playbook,
        send_fn:          SendFn,
        on_entry:         Optional[Callable[[TrafficEntry], None]] = None,
        global_variables: Optional[Dict[str, str]] = None,
    ) -> PlaybookRun:
        """
        Execute all frames in the playbook and return a PlaybookRun.

        For each frame:
          1. Resolve {{VAR}} placeholders (playbook vars override globals).
          2. Emit a TrafficEntry(direction="sent").
          3. Call send_fn(data, frame.direction) → list[bytes].
          4. Emit a TrafficEntry(direction="received") per received chunk.

        Args:
            playbook:         The playbook to run.
            send_fn:          Async callable: (data, direction) → [received_bytes, ...].
            on_entry:         Optional callback invoked immediately after each
                              TrafficEntry is appended, for live UI updates.
            global_variables: Optional global variable dict merged with
                              playbook.variables (playbook vars take priority).

        Returns:
            A completed PlaybookRun (not yet appended to playbook.runs).
        """
        run = PlaybookRun.create(playbook.label)

        merged_vars: Dict[str, str] = {}
        if global_variables:
            merged_vars.update(global_variables)
        merged_vars.update(playbook.variables)

        def _emit(entry: TrafficEntry) -> None:
            run.traffic.append(entry)
            if on_entry is not None:
                on_entry(entry)

        for frame in playbook.frames:
            try:
                data = resolve_hex(frame.raw_hex, merged_vars)
            except ValueError as exc:
                logger.error(
                    "PlaybookEngine: variable resolution failed for frame %r: %s",
                    frame.label, exc,
                )
                raise

            sent_entry = TrafficEntry.create_sent(data, frame.label)
            _emit(sent_entry)

            received_chunks = await send_fn(data, frame.direction)

            for chunk in received_chunks:
                recv_entry = TrafficEntry.create_received(chunk, frame.label)
                _emit(recv_entry)

        return run
