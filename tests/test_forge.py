"""Tests for the replay engine — core replay, frame selector, and direction filter."""

from __future__ import annotations

import asyncio

import pytest

from protopoke.config import ForwarderConfig
from protopoke.api import ProtoPokeAPI
from protopoke.models import Direction
from protopoke.forge.engine import parse_frame_selector, ForgeEngine
from protopoke.core.session import SessionRegistry
from tests.conftest import echo_server_ctx, free_port


async def capture_session(api: ProtoPokeAPI, listen_port: int, data: bytes) -> str:
    """Helper: connect through the proxy, send data, return session ID."""
    reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
    writer.write(data)
    await writer.drain()
    writer.write_eof()
    await asyncio.wait_for(reader.read(65536), timeout=5.0)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    await asyncio.sleep(0.1)  # Let session close
    sessions = api.list_sessions()
    return sessions[-1].id  # Most recent session


# ---------------------------------------------------------------------------
# parse_frame_selector unit tests (no network needed)
# ---------------------------------------------------------------------------

class TestParseFrameSelector:
    def test_single_number(self):
        assert parse_frame_selector("5") == {5}

    def test_range(self):
        assert parse_frame_selector("3-7") == {3, 4, 5, 6, 7}

    def test_range_single_element(self):
        assert parse_frame_selector("4-4") == {4}

    def test_comma_list(self):
        assert parse_frame_selector("3,4,7") == {3, 4, 7}

    def test_mixed(self):
        assert parse_frame_selector("3,5,7-9,11") == {3, 5, 7, 8, 9, 11}

    def test_whitespace_ignored(self):
        assert parse_frame_selector("1 , 3 - 5 , 8") == {1, 3, 4, 5, 8}

    def test_zero_is_valid(self):
        assert parse_frame_selector("0") == {0}

    def test_zero_based_range(self):
        assert parse_frame_selector("0-2") == {0, 1, 2}

    def test_overlapping_ranges_deduplicated(self):
        assert parse_frame_selector("1-5,3-7") == {1, 2, 3, 4, 5, 6, 7}

    def test_invalid_non_integer_raises(self):
        with pytest.raises(ValueError, match="non-negative integer"):
            parse_frame_selector("abc")

    def test_invalid_float_raises(self):
        with pytest.raises(ValueError):
            parse_frame_selector("1.5")

    def test_reversed_range_raises(self):
        with pytest.raises(ValueError, match="greater than end"):
            parse_frame_selector("9-3")

    def test_invalid_range_too_many_dashes_raises(self):
        with pytest.raises(ValueError, match="Invalid range"):
            parse_frame_selector("1-2-3")

    def test_empty_string_returns_empty_set(self):
        assert parse_frame_selector("") == set()

    def test_trailing_comma_ignored(self):
        # Extra empty tokens from trailing commas are skipped
        assert parse_frame_selector("1,2,") == {1, 2}


# ---------------------------------------------------------------------------
# Core replay (existing behaviour, unchanged)
# ---------------------------------------------------------------------------

class TestReplayCore:
    @pytest.mark.asyncio
    async def test_simple_replay(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test", listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                session_id = await capture_session(api, listen_port, b"replay me")
                result = await api.forge_session(session_id)

                assert result.success
                assert result.original_session_id == session_id
                sent     = b"".join(f.raw_bytes for f in result.frames_sent())
                received = b"".join(f.raw_bytes for f in result.frames_received())
                assert sent == b"replay me"
                assert received == b"replay me"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_replay_with_modified_frames(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test", listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                session_id = await capture_session(api, listen_port, b"original")
                session = api.get_session(session_id)
                client_frames = [f for f in session.frames if f.direction is Direction.CLIENT_TO_SERVER]
                assert client_frames

                modified = {client_frames[0].id: b"replaced"}
                result = await api.forge_session(session_id, modified_frames=modified)

                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"replaced"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_replay_unknown_session(self):
        engine = ForgeEngine(session_registry=SessionRegistry())
        result = await engine.forge_session("nonexistent-id")
        assert not result.success
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_replay_creates_new_session(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                session_id = await capture_session(api, listen_port, b"original")
                result = await api.forge_session(session_id)

                all_sessions = api.list_sessions()
                assert len(all_sessions) == 2
                ids = {s.id for s in all_sessions}
                assert session_id in ids
                assert result.replayed_session.id in ids
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_replay_to_different_server(self):
        async with echo_server_ctx() as (host1, port1):
            async with echo_server_ctx() as (host2, port2):
                listen_port = free_port()
                config = ForwarderConfig(name="Test",
                    listen_host="127.0.0.1", listen_port=listen_port,
                    upstream_host=host1, upstream_port=port1,
                )
                api = ProtoPokeAPI([config])
                await api.start()
                try:
                    session_id = await capture_session(api, listen_port, b"cross server")
                    result = await api.forge_session(
                        session_id, server_host=host2, server_port=port2,
                    )
                    assert result.success
                    received = b"".join(f.raw_bytes for f in result.frames_received())
                    assert received == b"cross server"
                finally:
                    await api.stop()


# ---------------------------------------------------------------------------
# Frame selector (integration with real sessions)
# ---------------------------------------------------------------------------

class TestFrameSelector:
    async def _setup(self, upstream_host, upstream_port):
        """Create a proxy and send 5 separate frames through it."""
        listen_port = free_port()
        config = ForwarderConfig(name="Test",
            listen_host="127.0.0.1", listen_port=listen_port,
            upstream_host=upstream_host, upstream_port=upstream_port,
            framer_name="delimiter",
            framer_kwargs={"delimiter": b"\n"},
        )
        api = ProtoPokeAPI([config])
        await api.start()

        # Send 5 newline-terminated lines so the delimiter framer creates 5 frames
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        for i in range(5):
            writer.write(f"frame{i}\n".encode())
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(reader.read(65536), timeout=5.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(0.1)

        session_id = api.list_sessions()[-1].id
        return api, session_id

    @pytest.mark.asyncio
    async def test_single_frame_selector(self):
        async with echo_server_ctx() as (h, p):
            api, session_id = await self._setup(h, p)
            try:
                result = await api.forge_session(session_id, frame_selector="2")
                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"frame2\n"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_range_selector(self):
        async with echo_server_ctx() as (h, p):
            api, session_id = await self._setup(h, p)
            try:
                result = await api.forge_session(session_id, frame_selector="1-3")
                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"frame1\nframe2\nframe3\n"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_comma_list_selector(self):
        async with echo_server_ctx() as (h, p):
            api, session_id = await self._setup(h, p)
            try:
                result = await api.forge_session(session_id, frame_selector="0,2,4")
                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"frame0\nframe2\nframe4\n"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_mixed_selector(self):
        async with echo_server_ctx() as (h, p):
            api, session_id = await self._setup(h, p)
            try:
                # "0,2-3" → frames 0, 2, 3
                result = await api.forge_session(session_id, frame_selector="0,2-3")
                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"frame0\nframe2\nframe3\n"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_selector_with_nonexistent_seqs_ignored(self):
        async with echo_server_ctx() as (h, p):
            api, session_id = await self._setup(h, p)
            try:
                # Sequences 0 and 99 requested; 99 doesn't exist — silently ignored
                result = await api.forge_session(session_id, frame_selector="0,99")
                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"frame0\n"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_selector_no_match_returns_failure(self):
        async with echo_server_ctx() as (h, p):
            api, session_id = await self._setup(h, p)
            try:
                # Sequences 99-100 don't exist
                result = await api.forge_session(session_id, frame_selector="99-100")
                assert not result.success
                assert "no" in result.error.lower() or "frame" in result.error.lower()
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_invalid_selector_returns_failure(self):
        async with echo_server_ctx() as (h, p):
            api, session_id = await self._setup(h, p)
            try:
                result = await api.forge_session(session_id, frame_selector="abc")
                assert not result.success
                assert "Invalid frame_selector" in result.error
            finally:
                await api.stop()


# ---------------------------------------------------------------------------
# Direction filter
# ---------------------------------------------------------------------------

class TestDirectionFilter:
    @pytest.mark.asyncio
    async def test_default_direction_is_client_to_server(self):
        async with echo_server_ctx() as (h, p):
            listen_port = free_port()
            config = ForwarderConfig(name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=h, upstream_port=p,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                session_id = await capture_session(api, listen_port, b"client data")
                result = await api.forge_session(session_id)
                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"client data"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_server_to_client_direction(self):
        """Replay server→client frames (sends the server's original response to the server)."""
        async with echo_server_ctx() as (h, p):
            listen_port = free_port()
            config = ForwarderConfig(name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=h, upstream_port=p,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                session_id = await capture_session(api, listen_port, b"ping")

                # The echo server replied with "ping"; replay that back to the server
                result = await api.forge_session(
                    session_id,
                    direction=Direction.SERVER_TO_CLIENT,
                )
                assert result.success
                # We sent the server's original reply ("ping") back to it
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"ping"
                # And the echo server echoed it back again
                received = b"".join(f.raw_bytes for f in result.frames_received())
                assert received == b"ping"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_no_frames_in_direction_returns_failure(self):
        """Asking for SERVER_TO_CLIENT on a session with no server frames fails cleanly."""
        from protopoke.core.session import Session, SessionRegistry
        from protopoke.models import SessionInfo, Frame
        from protopoke.forge.engine import ForgeEngine

        reg = SessionRegistry()
        info = SessionInfo.create("127.0.0.1", 1, "127.0.0.1", 2)
        info.state = __import__("protopoke.models", fromlist=["SessionState"]).SessionState.CLOSED
        sess = Session(info)
        # Only add a client→server frame; no server→client frames
        sess.add_frame(Frame.create(sess.id, Direction.CLIENT_TO_SERVER, b"data", 0))
        reg._sessions[sess.id] = sess

        engine = ForgeEngine(session_registry=reg)
        result = await engine.forge_session(
            sess.id,
            direction=Direction.SERVER_TO_CLIENT,
        )
        assert not result.success
        assert "server_to_client" in result.error

    @pytest.mark.asyncio
    async def test_direction_and_selector_combined(self):
        """direction + frame_selector work together."""
        async with echo_server_ctx() as (h, p):
            listen_port = free_port()
            config = ForwarderConfig(name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=h, upstream_port=p,
                framer_name="delimiter",
                framer_kwargs={"delimiter": b"\n"},
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
                for i in range(4):
                    writer.write(f"msg{i}\n".encode())
                await writer.drain()
                writer.write_eof()
                await asyncio.wait_for(reader.read(65536), timeout=5.0)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                await asyncio.sleep(0.1)

                session_id = api.list_sessions()[-1].id

                # Replay only sequences 1 and 3 from the client direction
                result = await api.forge_session(
                    session_id,
                    direction=Direction.CLIENT_TO_SERVER,
                    frame_selector="1,3",
                )
                assert result.success
                sent = b"".join(f.raw_bytes for f in result.frames_sent())
                assert sent == b"msg1\nmsg3\n"
            finally:
                await api.stop()
