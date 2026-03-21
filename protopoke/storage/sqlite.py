"""
SQLite-backed storage backend.

Persists sessions and frames to a local SQLite database file.  Uses the
standard-library ``sqlite3`` module with ``asyncio.run_in_executor`` so
database I/O doesn't block the event loop.

Schema
------
::

    sessions (
        id          TEXT PRIMARY KEY,
        client_host TEXT,
        client_port INTEGER,
        server_host TEXT,
        server_port INTEGER,
        state       TEXT,
        created_at  REAL,
        closed_at   REAL
    )

    frames (
        id              TEXT PRIMARY KEY,
        session_id      TEXT REFERENCES sessions(id),
        direction       TEXT,
        raw_bytes       BLOB,
        timestamp       REAL,
        sequence_number INTEGER,
        framer_name     TEXT
    )

Usage::

    storage = SqliteStorageBackend("path/to/sessions.db")
    await storage.initialize()    # create tables if not present

    await storage.save_session(session)
    await storage.save_frame(frame)

    sessions = await storage.list_sessions()
    frames   = await storage.load_frames(session_id)

    await storage.close()
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from functools import partial
from pathlib import Path
from typing import Optional

from ..models import Direction, Frame, SessionInfo, SessionState
from ..core.session import Session
from .base import StorageBackend

logger = logging.getLogger(__name__)

# DDL executed on first connect / initialize()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    client_host TEXT    NOT NULL,
    client_port INTEGER NOT NULL,
    server_host TEXT    NOT NULL,
    server_port INTEGER NOT NULL,
    state       TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    closed_at   REAL
);

CREATE TABLE IF NOT EXISTS frames (
    id              TEXT    PRIMARY KEY,
    session_id      TEXT    NOT NULL REFERENCES sessions(id),
    direction       TEXT    NOT NULL,
    raw_bytes       BLOB    NOT NULL,
    timestamp       REAL    NOT NULL,
    sequence_number INTEGER NOT NULL,
    framer_name     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_frames_session
    ON frames (session_id, sequence_number);
"""


class SqliteStorageBackend(StorageBackend):
    """
    Persistent storage backend using a local SQLite database.

    All database calls run in a thread-pool executor so they don't block
    the asyncio event loop.  A single dedicated ``sqlite3.Connection`` is
    reused across calls (``check_same_thread=False`` is safe because only
    the executor thread touches the connection at any one time due to the
    ``asyncio.lock``).

    Args:
        db_path: Path to the ``.db`` file.  Created if it doesn't exist.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """
        Open the database and create tables if they don't exist.

        Must be called once before any other method.
        """
        await self._run(self._sync_initialize)
        logger.info("SqliteStorageBackend initialised: %s", self._db_path)

    def _sync_initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,   # autocommit
        )
        self._conn.executescript(_SCHEMA)
        logger.debug("SQLite schema applied: %s", self._db_path)

    # ------------------------------------------------------------------
    # StorageBackend interface
    # ------------------------------------------------------------------

    async def save_session(self, session: Session) -> None:
        """Upsert a session row (insert or update on conflict)."""
        info = session.info
        await self._run(
            partial(self._sync_save_session, info)
        )

    def _sync_save_session(self, info: SessionInfo) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO sessions
                (id, client_host, client_port, server_host, server_port,
                 state, created_at, closed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                state     = excluded.state,
                closed_at = excluded.closed_at
            """,
            (
                info.id,
                info.client_host,
                info.client_port,
                info.server_host,
                info.server_port,
                info.state.value,
                info.created_at,
                info.closed_at,
            ),
        )

    async def load_session(self, session_id: str) -> Optional[Session]:
        """Load a session and its frames from the database."""
        return await self._run(partial(self._sync_load_session, session_id))

    def _sync_load_session(self, session_id: str) -> Optional[Session]:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        info = _row_to_session_info(row)
        session = Session(info)
        frames = self._sync_load_frames(session_id)
        for f in frames:
            session.add_frame(f)
        return session

    async def list_sessions(
        self, limit: int = 100, offset: int = 0
    ) -> list[SessionInfo]:
        """List stored sessions, newest first."""
        return await self._run(partial(self._sync_list_sessions, limit, offset))

    def _sync_list_sessions(
        self, limit: int, offset: int
    ) -> list[SessionInfo]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [_row_to_session_info(r) for r in rows]

    async def save_frame(self, frame: Frame) -> None:
        """Insert a frame row (ignored if the ID already exists)."""
        await self._run(partial(self._sync_save_frame, frame))

    def _sync_save_frame(self, frame: Frame) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT OR IGNORE INTO frames
                (id, session_id, direction, raw_bytes, timestamp,
                 sequence_number, framer_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                frame.id,
                frame.session_id,
                frame.direction.value,
                frame.raw_bytes,
                frame.timestamp,
                frame.sequence_number,
                frame.framer_name,
            ),
        )

    async def load_frames(self, session_id: str) -> list[Frame]:
        """Load all frames for *session_id*, ordered by sequence_number."""
        return await self._run(partial(self._sync_load_frames, session_id))

    def _sync_load_frames(self, session_id: str) -> list[Frame]:
        assert self._conn is not None
        rows = self._conn.execute(
            """
            SELECT id, session_id, direction, raw_bytes, timestamp,
                   sequence_number, framer_name
            FROM frames
            WHERE session_id = ?
            ORDER BY sequence_number
            """,
            (session_id,),
        ).fetchall()
        return [_row_to_frame(r) for r in rows]

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            await self._run(self._sync_close)

    def _sync_close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            logger.debug("SqliteStorageBackend closed: %s", self._db_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run(self, fn):
        """Run *fn* (a zero-argument callable) in a thread-pool executor, serialised by a lock."""
        loop = asyncio.get_running_loop()
        async with self._lock:
            return await loop.run_in_executor(None, fn)


# ---------------------------------------------------------------------------
# Row ↔ model helpers
# ---------------------------------------------------------------------------

def _row_to_session_info(row: tuple) -> SessionInfo:
    (
        id_, client_host, client_port, server_host, server_port,
        state, created_at, closed_at,
    ) = row
    return SessionInfo(
        id=id_,
        client_host=client_host,
        client_port=client_port,
        server_host=server_host,
        server_port=server_port,
        state=SessionState(state),
        created_at=created_at,
        closed_at=closed_at,
    )


def _row_to_frame(row: tuple) -> Frame:
    (
        id_, session_id, direction, raw_bytes, timestamp,
        sequence_number, framer_name,
    ) = row
    return Frame(
        id=id_,
        session_id=session_id,
        direction=Direction(direction),
        raw_bytes=bytes(raw_bytes),
        timestamp=timestamp,
        sequence_number=sequence_number,
        framer_name=framer_name,
    )
