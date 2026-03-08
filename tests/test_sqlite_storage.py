"""Tests for SqliteStorageBackend."""

from __future__ import annotations

import pytest

from protopoke.models import Direction, Frame, SessionState
from protopoke.core.session import Session, SessionRegistry
from protopoke.storage.sqlite import SqliteStorageBackend


def make_session(client_host="127.0.0.1", client_port=50000,
                 server_host="10.0.0.1", server_port=443) -> Session:
    registry = SessionRegistry()
    return registry.create(client_host, client_port, server_host, server_port)


def make_frame(session_id: str, direction=Direction.CLIENT_TO_SERVER,
               data=b"\x01\x02\x03", seq=0) -> Frame:
    return Frame.create(session_id, direction, data, seq)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.mark.asyncio
class TestSqliteStorageBackend:
    async def test_initialize_creates_db(self, tmp_path):
        backend = SqliteStorageBackend(tmp_path / "test.db")
        await backend.initialize()
        assert (tmp_path / "test.db").exists()
        await backend.close()

    async def test_save_and_load_session(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()

        session = make_session()
        await backend.save_session(session)

        loaded = await backend.load_session(session.id)
        assert loaded is not None
        assert loaded.id == session.id
        assert loaded.info.client_host == session.info.client_host
        assert loaded.info.server_port == session.info.server_port

        await backend.close()

    async def test_load_session_not_found(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()
        result = await backend.load_session("nonexistent-id")
        assert result is None
        await backend.close()

    async def test_save_and_load_frame(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()

        session = make_session()
        await backend.save_session(session)

        frame = make_frame(session.id, data=b"\xDE\xAD\xBE\xEF")
        await backend.save_frame(frame)

        frames = await backend.load_frames(session.id)
        assert len(frames) == 1
        assert frames[0].raw_bytes == b"\xDE\xAD\xBE\xEF"
        assert frames[0].direction is Direction.CLIENT_TO_SERVER

        await backend.close()

    async def test_load_frames_ordered_by_sequence(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()

        session = make_session()
        await backend.save_session(session)

        for seq in [2, 0, 1]:
            await backend.save_frame(make_frame(session.id, seq=seq, data=bytes([seq])))

        frames = await backend.load_frames(session.id)
        assert [f.sequence_number for f in frames] == [0, 1, 2]

        await backend.close()

    async def test_list_sessions_newest_first(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()

        s1 = make_session(client_port=50001)
        s2 = make_session(client_port=50002)
        await backend.save_session(s1)
        await backend.save_session(s2)

        sessions = await backend.list_sessions(limit=10)
        assert len(sessions) == 2
        # Newest first (s2 created after s1)
        assert sessions[0].id == s2.id or sessions[1].id == s1.id

        await backend.close()

    async def test_upsert_session_state(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()

        session = make_session()
        await backend.save_session(session)

        session.mark_closed()
        await backend.save_session(session)

        loaded = await backend.load_session(session.id)
        assert loaded is not None
        assert loaded.info.state is SessionState.CLOSED

        await backend.close()

    async def test_duplicate_frame_ignored(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()

        session = make_session()
        await backend.save_session(session)

        frame = make_frame(session.id)
        await backend.save_frame(frame)
        await backend.save_frame(frame)  # duplicate — should be silently ignored

        frames = await backend.load_frames(session.id)
        assert len(frames) == 1

        await backend.close()

    async def test_frames_include_raw_bytes_as_bytes_not_memoryview(self, db_path):
        backend = SqliteStorageBackend(db_path)
        await backend.initialize()

        session = make_session()
        await backend.save_session(session)

        frame = make_frame(session.id, data=b"\x00\x01\x02")
        await backend.save_frame(frame)

        frames = await backend.load_frames(session.id)
        assert isinstance(frames[0].raw_bytes, bytes)

        await backend.close()
