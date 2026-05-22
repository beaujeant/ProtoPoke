"""Tests for custom-destination playbook connection lifecycle.

These tests cover the Forge behaviour where a playbook is configured with a
custom host/port (not a proxy session):

  * The first run opens a persistent TCP connection and records it on the
    playbook so subsequent runs reuse the same session.
  * A plain receive-timeout does not close the connection — the operator can
    send more frames on the same socket.
  * When the server drops the connection the session is marked CLOSED
    proactively and a SessionClosedEvent is emitted, even between runs.
  * terminate_session works on forge-owned sessions.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig
from protopoke.events.bus import SessionClosedEvent, SessionOpenedEvent
from protopoke.forge.models import Playbook, PlaybookFrame
from tests.conftest import free_port


# ---------------------------------------------------------------------------
# Tiny test servers
# ---------------------------------------------------------------------------

@asynccontextmanager
async def quiet_server_ctx():
    """A TCP server that reads forever and never writes a reply.

    Useful for verifying that a receive-timeout does not tear down the
    connection — the server keeps the socket open until the client closes it.
    """
    async def handler(reader, writer):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    bound_port = server.sockets[0].getsockname()[1]
    try:
        yield "127.0.0.1", bound_port
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def close_after_one_msg_ctx():
    """Server that accepts one frame then closes the connection."""
    async def handler(reader, writer):
        try:
            await reader.read(4096)
            writer.close()
        except Exception:
            pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    bound_port = server.sockets[0].getsockname()[1]
    try:
        yield "127.0.0.1", bound_port
    finally:
        server.close()
        await server.wait_closed()


def _api() -> ProtoPokeAPI:
    """A ProtoPokeAPI with no forwarders — we only need forge + registry."""
    return ProtoPokeAPI([ForwarderConfig(name="none", enabled=False)])


# ---------------------------------------------------------------------------
# Reuse-on-subsequent-run tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_custom_playbook_keeps_connection_alive():
    """After a custom run, the TCP session should remain active and the
    playbook should pin it for reuse."""
    async with quiet_server_ctx() as (host, port):
        api = _api()
        pb = Playbook.create(label="t", host=host, port=port, response_window=0.2)
        pb.frames.append(PlaybookFrame.create("hello", "de ad be ef"))

        assert pb.source_session_id is None
        run = await api.run_playbook(pb)
        assert len(run.traffic) >= 1  # at least the sent frame

        # The playbook should have been pinned to the new forge session.
        assert pb.source_session_id is not None, (
            "playbook.source_session_id must be set after a successful custom run"
        )

        # The session must still be active — a receive-timeout is NOT a close.
        session = api.get_session(pb.source_session_id)
        assert session is not None
        assert session.is_active(), (
            "session should remain ACTIVE when only the receive_timeout elapsed"
        )
        assert api.forge_engine.is_forge_session(pb.source_session_id)


@pytest.mark.asyncio
async def test_subsequent_run_reuses_forge_session():
    """Running the same custom playbook twice should not open a second
    connection — the pinned session_id is reused."""
    async with quiet_server_ctx() as (host, port):
        api = _api()
        pb = Playbook.create(label="t", host=host, port=port, response_window=0.2)
        pb.frames.append(PlaybookFrame.create("a", "01"))

        await api.run_playbook(pb)
        first_id = pb.source_session_id
        assert first_id is not None

        await api.run_playbook(pb)
        assert pb.source_session_id == first_id, (
            "the playbook must reuse the previous forge session, "
            "not open a fresh one each run"
        )

        # Only one forge-owned session should exist.
        forge_sessions = [
            s for s in api.list_sessions()
            if api.forge_engine.is_forge_session(s.id)
        ]
        assert len(forge_sessions) == 1


# ---------------------------------------------------------------------------
# Proactive server-initiated close
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_server_close_marks_session_closed_without_next_send():
    """When the server drops the connection, the background reader should
    mark the session CLOSED and fire SessionClosedEvent without waiting for
    the next send_on_forge_session call."""
    async with close_after_one_msg_ctx() as (host, port):
        api = _api()

        closed_events: list[str] = []

        async def on_closed(event: SessionClosedEvent) -> None:
            closed_events.append(event.session.id)

        api.on_session_closed(on_closed)

        pb = Playbook.create(label="t", host=host, port=port, response_window=0.3)
        pb.frames.append(PlaybookFrame.create("a", "01 02"))

        await api.run_playbook(pb)

        # Give the background reader a tick to observe EOF after the server
        # closed its side of the socket.
        for _ in range(20):
            session = api.get_session(pb.source_session_id) if pb.source_session_id else None
            latest = pb.source_session_id
            # The run's finally block may have cleared source_session_id
            # already — fall back to scanning the registry.
            if latest is None and api.list_sessions():
                latest = api.list_sessions()[-1].id
                session = api.get_session(latest)
            if session is not None and not session.is_active():
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("session was never marked CLOSED")

        assert closed_events, "SessionClosedEvent must fire when server drops the connection"

        # The playbook must no longer pin a dead session.
        assert pb.source_session_id is None


@pytest.mark.asyncio
async def test_next_run_after_server_close_opens_new_session():
    """After the server closes, running the playbook again should open a
    fresh TCP connection rather than failing."""
    async with close_after_one_msg_ctx() as (host, port):
        api = _api()
        pb = Playbook.create(label="t", host=host, port=port, response_window=0.3)
        pb.frames.append(PlaybookFrame.create("a", "01"))

        await api.run_playbook(pb)
        await asyncio.sleep(0.1)  # let reader observe EOF

        # Second run should open a new session (a fresh forge connection).
        await api.run_playbook(pb)

        # We expect two distinct forge sessions in the registry (both closed
        # by now since each one only survives a single message from the
        # server).
        forge_sessions = [
            s for s in api.list_sessions()
            if s.info.client_host == "forge"
        ]
        assert len(forge_sessions) == 2, (
            f"expected two distinct forge sessions, got {len(forge_sessions)}"
        )


# ---------------------------------------------------------------------------
# Operator-initiated close
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_terminate_session_closes_forge_session():
    """api.terminate_session() must tear down forge-owned sessions and fire
    the SessionClosedEvent."""
    async with quiet_server_ctx() as (host, port):
        api = _api()
        opened: list[str] = []
        closed: list[str] = []

        async def on_opened(event: SessionOpenedEvent) -> None:
            opened.append(event.session.id)

        async def on_closed(event: SessionClosedEvent) -> None:
            closed.append(event.session.id)

        api.on_session_opened(on_opened)
        api.on_session_closed(on_closed)

        session_id = await api.open_forge_session(host, port)
        assert session_id in opened
        assert api.forge_engine.is_forge_session(session_id)

        ok = await api.terminate_session(session_id)
        assert ok is True

        session = api.get_session(session_id)
        assert session is not None
        assert not session.is_active()
        assert session_id in closed
        assert not api.forge_engine.is_forge_session(session_id)


# ---------------------------------------------------------------------------
# Receive-timeout alone does NOT close
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_receive_timeout_does_not_close_connection():
    """A short response_window elapsed without data must NOT tear the
    connection down — the operator may want to send more frames."""
    async with quiet_server_ctx() as (host, port):
        api = _api()
        session_id = await api.open_forge_session(host, port)

        result = await api.send_on_forge_session(
            session_id=session_id,
            data=b"\x01\x02",
            receive_timeout=0.1,
        )
        assert result.success is True
        assert result.response_packets == []

        session = api.get_session(session_id)
        assert session is not None
        assert session.is_active(), (
            "receive_timeout is not an error — the session must stay open"
        )
        assert api.forge_engine.is_forge_session(session_id)

        # A second send on the same session must still succeed.
        result2 = await api.send_on_forge_session(
            session_id=session_id,
            data=b"\x03",
            receive_timeout=0.1,
        )
        assert result2.success is True

        await api.terminate_session(session_id)
