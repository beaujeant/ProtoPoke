"""
Session model and registry.

A Session represents one proxied TCP connection. The SessionRegistry is the
single place to create, look up, and track all sessions.

Design:
    Session     — holds SessionInfo metadata + list of captured Frames
    SessionRegistry — dict-backed store; no database yet

Memory:
    Frames are kept in Session.frames in memory. For long-running captures
    with high traffic, you'd want to flush frames to the storage backend
    periodically. That's a future concern; for a personal research tool,
    in-memory is fine.

Persistence path:
    When you add a SqliteStorageBackend, the storage layer subscribes to
    FrameCapturedEvent and SessionClosedEvent and writes to disk. The in-memory
    Session.frames list remains as a fast cache; the DB is the durable record.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from ..models import Frame, SessionInfo, SessionState

logger = logging.getLogger(__name__)


class Session:
    """
    One proxied TCP connection.

    Holds session metadata (as a SessionInfo) plus the ordered list of
    all captured frames in this session.

    The live asyncio stream objects (reader/writer) are NOT stored here —
    they live only in the relay tasks. This keeps Session serializable and
    usable after the connection closes.
    """

    def __init__(self, info: SessionInfo) -> None:
        self.info   = info
        self.frames: list[Frame] = []

    # ------------------------------------------------------------------
    # Properties / shorthands
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self.info.id

    @property
    def state(self) -> SessionState:
        return self.info.state

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def add_frame(self, frame: Frame) -> None:
        """Append a captured frame. Called by the relay."""
        self.frames.append(frame)

    def mark_active(self) -> None:
        self.info.state = SessionState.ACTIVE

    def mark_closed(self) -> None:
        self.info.state = SessionState.CLOSED
        self.info.closed_at = time.time()

    def mark_only_server(self) -> None:
        """Client disconnected; server side still up."""
        self.info.state = SessionState.ONLY_SERVER

    def mark_only_client(self) -> None:
        """Server disconnected; client side still up."""
        self.info.state = SessionState.ONLY_CLIENT

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def frames_for_direction(self, direction) -> list[Frame]:
        """Return frames filtered to one direction."""
        return [f for f in self.frames if f.direction == direction]

    def is_active(self) -> bool:
        return self.info.state in (
            SessionState.CONNECTING,
            SessionState.ACTIVE,
            SessionState.ONLY_SERVER,
            SessionState.ONLY_CLIENT,
        )

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"Session(id={self.id[:8]}... "
            f"{self.info.client_host}:{self.info.client_port}"
            f" -> {self.info.server_host}:{self.info.server_port} "
            f"state={self.info.state.value} "
            f"frames={len(self.frames)})"
        )


class SessionRegistry:
    """
    Central store for all sessions (active and historical).

    The ProxyEngine creates sessions here on new connections.
    The relay updates state via mark_active / mark_closed.
    The ProxyAPI queries sessions for the operator.

    Not thread-safe by design — all interaction happens within the same
    asyncio event loop, so no locks are needed.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def create(
        self,
        client_host: str,
        client_port: int,
        server_host: str,
        server_port: int,
    ) -> Session:
        """
        Create and register a new session.

        Returns the new Session in CONNECTING state.
        """
        info    = SessionInfo.create(client_host, client_port, server_host, server_port)
        session = Session(info)
        self._sessions[session.id] = session
        logger.info(
            "Session created: %s (client=%s:%d server=%s:%d)",
            session.id, client_host, client_port, server_host, server_port,
        )
        return session

    def mark_active(self, session_id: str) -> None:
        """Transition session to ACTIVE state."""
        session = self._sessions.get(session_id)
        if session:
            session.mark_active()
            logger.info("Session active: %s", session_id)

    def mark_closed(self, session_id: str) -> None:
        """Transition session to CLOSED state."""
        session = self._sessions.get(session_id)
        if session:
            session.mark_closed()
            logger.info(
                "Session closed: %s (frames captured: %d)",
                session_id, len(session.frames),
            )

    def mark_only_server(self, session_id: str) -> None:
        """Client disconnected; server side still up."""
        session = self._sessions.get(session_id)
        if session:
            session.mark_only_server()
            logger.info("Session only-server: %s", session_id)

    def mark_only_client(self, session_id: str) -> None:
        """Server disconnected; client side still up."""
        session = self._sessions.get(session_id)
        if session:
            session.mark_only_client()
            logger.info("Session only-client: %s", session_id)

    def delete(self, session_id: str) -> bool:
        """
        Permanently remove a session from the registry.

        The session must be closed first; callers should terminate it before
        deleting.  Returns ``True`` if the session existed and was removed,
        ``False`` if it was not found.
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info("Session deleted from registry: %s", session_id)
            return True
        return False

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, session_id: str) -> Optional[Session]:
        """Look up a session by ID. Returns None if not found."""
        return self._sessions.get(session_id)

    def active_sessions(self) -> list[Session]:
        """All sessions that are not yet closed."""
        return [s for s in self._sessions.values() if s.is_active()]

    def all_sessions(self) -> list[Session]:
        """All sessions, including closed ones."""
        return list(self._sessions.values())

    def __len__(self) -> int:
        return len(self._sessions)

    def __repr__(self) -> str:
        active = sum(1 for s in self._sessions.values() if s.is_active())
        return f"SessionRegistry(total={len(self._sessions)}, active={active})"
