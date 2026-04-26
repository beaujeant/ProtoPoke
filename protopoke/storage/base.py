"""
Storage backend interface and built-in implementations.

The storage layer is responsible for persisting sessions and frames across
proxy restarts. The interface is defined here as an abstract base class.

Included backends:
    NullStorageBackend   — no-op; drops everything (default for in-memory use)
    SqliteStorageBackend — persists sessions and frames to a local SQLite file
                           (see storage/sqlite.py)

How persistence integrates:
    ProtoPokeAPI subscribes a storage backend to the event bus:

        async def on_frame(event: FrameCapturedEvent):
            await storage.save_frame(event.frame)

        api.event_bus.subscribe(FrameCapturedEvent, on_frame)

    The storage backend is completely decoupled from the proxy core.
    Swapping from NullStorage to SqliteStorage is a one-line change in ProtoPokeAPI.

SQLite schema (implemented in storage/sqlite.py):

    CREATE TABLE sessions (
        id          TEXT PRIMARY KEY,
        client_host TEXT, client_port INTEGER,
        server_host TEXT, server_port INTEGER,
        state       TEXT,
        created_at  REAL,
        closed_at   REAL
    );

    CREATE TABLE frames (
        id              TEXT PRIMARY KEY,
        session_id      TEXT REFERENCES sessions(id),
        direction       TEXT,
        raw_bytes       BLOB,
        timestamp       REAL,
        sequence_number INTEGER,
        framer_name     TEXT
    );
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..models import Frame, SessionInfo
from ..core.session import Session


class StorageBackend(ABC):
    """
    Abstract interface for session/frame persistence.

    All methods are async to allow non-blocking I/O backends (e.g. aiosqlite).
    Synchronous backends just return values without awaiting anything.
    """

    @abstractmethod
    async def save_session(self, session: Session) -> None:
        """Persist a session's metadata. Called on session open and close."""
        ...

    @abstractmethod
    async def load_session(self, session_id: str) -> Optional[Session]:
        """Load a session by ID. Returns None if not found."""
        ...

    @abstractmethod
    async def list_sessions(self, limit: int = 100, offset: int = 0) -> list[SessionInfo]:
        """
        List stored sessions (metadata only, no frames).

        Args:
            limit:  Maximum number of results.
            offset: Skip this many results (for pagination).
        """
        ...

    @abstractmethod
    async def save_frame(self, frame: Frame) -> None:
        """Persist a single captured frame."""
        ...

    @abstractmethod
    async def load_frames(self, session_id: str) -> list[Frame]:
        """Load all frames for a session, ordered by sequence_number."""
        ...

    async def close(self) -> None:
        """Clean up resources (close DB connections, flush writes, etc.)."""
        pass


class NullStorageBackend(StorageBackend):
    """
    No-op backend. Discards everything.

    Use when you only need in-memory operation and don't want persistence.
    The SessionRegistry already keeps all sessions and frames in memory;
    this backend just satisfies the StorageBackend interface without
    doing anything extra.
    """

    async def save_session(self, session: Session) -> None:
        pass

    async def load_session(self, session_id: str) -> Optional[Session]:
        return None

    async def list_sessions(self, limit: int = 100, offset: int = 0) -> list[SessionInfo]:
        return []

    async def save_frame(self, frame: Frame) -> None:
        pass

    async def load_frames(self, session_id: str) -> list[Frame]:
        return []
