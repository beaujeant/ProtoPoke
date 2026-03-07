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
    ReplayEngine replays client→server frames from a captured Session to a
    target server, captures the server's responses, and returns a new Session
    containing both the sent frames and the received responses.

    The new session is registered in the SessionRegistry, so it appears in
    the API's session list like any other session. It can itself be replayed,
    compared, or have its frames inspected.

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
import time
from dataclasses import dataclass, field
from typing import Optional

from ..models import Direction, Frame, SessionInfo
from ..core.session import Session, SessionRegistry
from ..framing import create_framer

logger = logging.getLogger(__name__)


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

    def client_frames_sent(self) -> list[Frame]:
        """Frames that were sent to the server during replay."""
        return [
            f for f in self.replayed_session.frames
            if f.direction is Direction.CLIENT_TO_SERVER
        ]

    def server_frames_received(self) -> list[Frame]:
        """Frames received from the server during replay."""
        return [
            f for f in self.replayed_session.frames
            if f.direction is Direction.SERVER_TO_CLIENT
        ]

    def total_bytes_sent(self) -> int:
        return sum(len(f.raw_bytes) for f in self.client_frames_sent())

    def total_bytes_received(self) -> int:
        return sum(len(f.raw_bytes) for f in self.server_frames_received())


class ReplayEngine:
    """
    Replays captured TCP sessions against a target server.

    Usage:
        engine = ReplayEngine(session_registry)

        result = await engine.replay_session(
            session_id="...",
            server_host="127.0.0.1",
            server_port=9090,
        )

        if result.success:
            for frame in result.server_frames_received():
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

    async def replay_session(
        self,
        session_id:      str,
        server_host:     Optional[str]         = None,
        server_port:     Optional[int]         = None,
        frame_delay:     float                 = 0.0,
        modified_frames: Optional[dict[str, bytes]] = None,
    ) -> ReplayResult:
        """
        Replay a captured session.

        Args:
            session_id:      ID of the session to replay. Must exist in registry.
            server_host:     Override target host (default: same as original session).
            server_port:     Override target port (default: same as original session).
            frame_delay:     Seconds to wait between sending frames. Useful for
                             rate-limited servers. 0 = send as fast as possible.
            modified_frames: Dict mapping original frame_id → replacement bytes.
                             Frames not in the dict are sent with original bytes.
                             Use this for fuzzing / targeted modification.

        Returns:
            ReplayResult with the new session and metadata.
        """
        original = self._session_registry.get(session_id)
        if not original:
            # Return a failed result with a stub session
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

        # Collect client frames in sequence order
        client_frames = sorted(
            (f for f in original.frames if f.direction is Direction.CLIENT_TO_SERVER),
            key=lambda f: f.sequence_number,
        )

        if not client_frames:
            stub_info = SessionInfo.create("replay", 0, target_host, target_port)
            stub = Session(stub_info)
            return ReplayResult(
                original_session_id=session_id,
                replayed_session=stub,
                success=False,
                error="No client→server frames to replay",
                completed_at=time.time(),
            )

        # Create a new session in the registry for this replay
        replayed = self._session_registry.create(
            client_host="replay",
            client_port=0,
            server_host=target_host,
            server_port=target_port,
        )

        logger.info(
            "Replaying session %s → new session %s to %s:%d (%d client frames)",
            session_id, replayed.id, target_host, target_port, len(client_frames),
        )

        result = ReplayResult(
            original_session_id=session_id,
            replayed_session=replayed,
            success=False,
        )

        try:
            await self._execute_replay(
                replayed_session=replayed,
                client_frames=client_frames,
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
        client_frames:    list[Frame],
        target_host:      str,
        target_port:      int,
        frame_delay:      float,
        modified_frames:  dict[str, bytes],
        result:           ReplayResult,
    ) -> None:
        """
        Internal: connect to the server, send frames, capture responses.
        """
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
            # Send all client frames to the server
            for original_frame in client_frames:
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

            # Signal EOF to the server (we're done sending)
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
                len(result.client_frames_sent()), result.total_bytes_sent(),
                len(result.server_frames_received()), result.total_bytes_received(),
            )

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
