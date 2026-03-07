"""Tests for the replay engine."""

from __future__ import annotations

import asyncio

import pytest

from tcpproxy.config import ProxyConfig
from tcpproxy.api import ProxyAPI
from tcpproxy.models import Direction
from tests.conftest import echo_server_ctx, free_port


async def capture_session(api: ProxyAPI, listen_port: int, data: bytes) -> str:
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


class TestReplayEngine:
    @pytest.mark.asyncio
    async def test_simple_replay(self):
        """Replay a captured session and verify the server sees the same bytes."""
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
            await api.start()

            try:
                session_id = await capture_session(api, listen_port, b"replay me")

                result = await api.replay_session(session_id)

                assert result.success
                assert result.original_session_id == session_id

                sent = b"".join(f.raw_bytes for f in result.client_frames_sent())
                received = b"".join(f.raw_bytes for f in result.server_frames_received())

                assert sent == b"replay me"
                assert received == b"replay me"  # Echo server
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_replay_with_modified_frames(self):
        """Replay with a modified frame and verify the server sees the modification."""
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
            await api.start()

            try:
                session_id = await capture_session(api, listen_port, b"original")

                session = api.get_session(session_id)
                client_frames = [
                    f for f in session.frames
                    if f.direction is Direction.CLIENT_TO_SERVER
                ]
                assert client_frames

                # Replace first frame's bytes
                modified = {client_frames[0].id: b"replaced"}
                result = await api.replay_session(session_id, modified_frames=modified)

                assert result.success
                sent = b"".join(f.raw_bytes for f in result.client_frames_sent())
                assert sent == b"replaced"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_replay_unknown_session(self):
        """Replaying a nonexistent session returns a failed result."""
        from tcpproxy.core.session import SessionRegistry
        from tcpproxy.replay.engine import ReplayEngine

        reg = ReplayEngine(session_registry=SessionRegistry())
        result = await reg.replay_session("nonexistent-id")
        assert not result.success
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_replay_creates_new_session(self):
        """The replay creates a new session entry in the registry."""
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
            await api.start()

            try:
                session_id = await capture_session(api, listen_port, b"original")
                result = await api.replay_session(session_id)

                # There should now be 2 sessions: original + replay
                all_sessions = api.list_sessions()
                assert len(all_sessions) == 2

                ids = {s.id for s in all_sessions}
                assert session_id in ids
                assert result.replayed_session.id in ids
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_replay_to_different_port(self):
        """Replay can target a different server than the original."""
        async with echo_server_ctx() as (host1, port1):
            async with echo_server_ctx() as (host2, port2):
                listen_port = free_port()
                config = ProxyConfig(
                    listen_host="127.0.0.1", listen_port=listen_port,
                    upstream_host=host1, upstream_port=port1,
                )
                api = ProxyAPI(config)
                await api.start()

                try:
                    session_id = await capture_session(api, listen_port, b"cross server")

                    # Replay to the second echo server
                    result = await api.replay_session(
                        session_id,
                        server_host=host2,
                        server_port=port2,
                    )

                    assert result.success
                    received = b"".join(f.raw_bytes for f in result.server_frames_received())
                    assert received == b"cross server"
                finally:
                    await api.stop()
