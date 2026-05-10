"""
Integration tests for the TCP proxy.

These tests start real asyncio TCP servers and run the full proxy stack
end-to-end: real network connections, real framing, real interception.

Port allocation:
    Each test uses conftest.echo_server_ctx() which binds to port 0
    (OS-assigned free port) to avoid conflicts.
"""

from __future__ import annotations

import asyncio

import pytest

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig
from protopoke.models import Direction
from tests.conftest import echo_server_ctx, free_port


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def send_recv(host: str, port: int, data: bytes, timeout: float = 5.0) -> bytes:
    """Connect, send data, receive all available response, close."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(data)
        await writer.drain()
        writer.write_eof()
        response = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Basic forwarding
# ---------------------------------------------------------------------------

class TestPassthroughProxy:
    @pytest.mark.asyncio
    async def test_forwards_data_to_upstream(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                response = await send_recv("127.0.0.1", listen_port, b"hello proxy")
                assert response == b"hello proxy"
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_captures_frames_both_directions(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                await send_recv("127.0.0.1", listen_port, b"test data")
                await asyncio.sleep(0.1)  # Let relay tasks finish cleanup

                sessions = api.list_sessions()
                assert len(sessions) == 1

                session = sessions[0]
                client_frames = api.get_frames(session.id, Direction.CLIENT_TO_SERVER)
                server_frames = api.get_frames(session.id, Direction.SERVER_TO_CLIENT)

                assert len(client_frames) >= 1
                assert len(server_frames) >= 1

                client_data = b"".join(f.raw_bytes for f in client_frames)
                server_data = b"".join(f.raw_bytes for f in server_frames)

                assert client_data == b"test data"
                assert server_data == b"test data"

            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_handles_multiple_sessions(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                # Run 3 sessions concurrently
                responses = await asyncio.gather(
                    send_recv("127.0.0.1", listen_port, b"client-1"),
                    send_recv("127.0.0.1", listen_port, b"client-2"),
                    send_recv("127.0.0.1", listen_port, b"client-3"),
                )
                assert set(responses) == {b"client-1", b"client-2", b"client-3"}
                await asyncio.sleep(0.1)
                assert len(api.list_sessions()) == 3
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_session_state_lifecycle(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            # Force the legacy "client disconnect tears down the upstream"
            # behaviour so the session reliably reaches CLOSED without us
            # having to terminate it manually.
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                keep_upstream_on_client_disconnect=False,
            )
            api = ProtoPokeAPI([config])
            opened_sessions = []
            closed_sessions = []

            async def on_open(event):
                opened_sessions.append(event.session.id)

            async def on_close(event):
                closed_sessions.append(event.session.id)

            api.on_session_opened(on_open)
            api.on_session_closed(on_close)
            await api.start()

            try:
                await send_recv("127.0.0.1", listen_port, b"lifecycle test")
                await asyncio.sleep(0.2)

                assert len(opened_sessions) == 1
                assert len(closed_sessions) == 1
                assert opened_sessions[0] == closed_sessions[0]
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_client_disconnect_keeps_upstream_alive(self):
        """
        With the default ``keep_upstream_on_client_disconnect=True`` setting,
        a client disconnect must NOT close the upstream server connection.
        The session transitions to ONLY_SERVER and the server-side writer is
        still available so Forge can keep injecting bytes.
        """
        from protopoke.models import SessionState

        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", listen_port
                )
                writer.write(b"hello")
                await writer.drain()
                await asyncio.sleep(0.1)

                sessions = api.list_active_sessions()
                assert len(sessions) == 1
                session_id = sessions[0].id

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                await asyncio.sleep(0.2)

                # Session must still be active (ONLY_SERVER) and inject must work.
                session = api.get_session(session_id)
                assert session is not None
                assert session.state is SessionState.ONLY_SERVER

                injected = await api.inject_to_server(session_id, b"after-close")
                assert injected is True
            finally:
                await api.stop()

    @pytest.mark.asyncio
    async def test_event_bus_frame_events(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            captured = []

            async def on_frame(event):
                captured.append(event.frame)

            api.on_frame_captured(on_frame)
            await api.start()

            try:
                await send_recv("127.0.0.1", listen_port, b"events!")
                await asyncio.sleep(0.1)
                assert len(captured) >= 1
            finally:
                await api.stop()


# ---------------------------------------------------------------------------
# Interception
# ---------------------------------------------------------------------------

class TestInterception:
    @pytest.mark.asyncio
    async def test_intercept_and_forward(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                tamper_enabled=True,
            )
            api = ProtoPokeAPI([config])
            await api.start()

            async def handle_intercepts():
                while True:
                    try:
                        unit = await asyncio.wait_for(api.get_next_intercepted(), timeout=3.0)
                        api.forward(unit.id)
                    except asyncio.TimeoutError:
                        break

            intercept_task = asyncio.create_task(handle_intercepts())

            try:
                response = await send_recv("127.0.0.1", listen_port, b"intercept me")
                assert response == b"intercept me"
            finally:
                await api.stop()
                intercept_task.cancel()
                try:
                    await intercept_task
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass

    @pytest.mark.asyncio
    async def test_intercept_and_modify(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                tamper_enabled=True,
            )
            api = ProtoPokeAPI([config])
            await api.start()

            async def handle_intercepts():
                while True:
                    try:
                        unit = await asyncio.wait_for(api.get_next_intercepted(), timeout=3.0)
                        if unit.frame.direction is Direction.CLIENT_TO_SERVER:
                            # Modify what the client sends
                            api.modify_and_forward(unit.id, b"modified by proxy")
                        else:
                            # Forward server responses as-is
                            api.forward(unit.id)
                    except asyncio.TimeoutError:
                        break

            intercept_task = asyncio.create_task(handle_intercepts())

            try:
                response = await send_recv("127.0.0.1", listen_port, b"original")
                # Echo server echoes what we actually sent (which was modified)
                assert response == b"modified by proxy"
            finally:
                await api.stop()
                intercept_task.cancel()
                try:
                    await intercept_task
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass

    @pytest.mark.asyncio
    async def test_intercept_and_drop(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                tamper_enabled=True,
            )
            api = ProtoPokeAPI([config])
            await api.start()

            async def handle_intercepts():
                while True:
                    try:
                        unit = await asyncio.wait_for(api.get_next_intercepted(), timeout=3.0)
                        if unit.frame.direction is Direction.CLIENT_TO_SERVER:
                            api.drop(unit.id)
                        else:
                            api.forward(unit.id)
                    except asyncio.TimeoutError:
                        break

            intercept_task = asyncio.create_task(handle_intercepts())

            try:
                # Drop the client->server frame; server should not echo anything
                reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
                writer.write(b"drop this")
                await writer.drain()
                writer.write_eof()

                # Give some time; no response expected
                await asyncio.sleep(0.3)
                response = b""
                try:
                    response = await asyncio.wait_for(reader.read(4096), timeout=0.5)
                except asyncio.TimeoutError:
                    pass

                writer.close()
                assert response == b""
            finally:
                await api.stop()
                intercept_task.cancel()
                try:
                    await intercept_task
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass

    @pytest.mark.asyncio
    async def test_toggle_intercept_at_runtime(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                tamper_enabled=True,
            )
            api = ProtoPokeAPI([config])
            await api.start()

            # Disable interception -- everything should flow through
            api.tamper_enabled = False

            try:
                response = await send_recv("127.0.0.1", listen_port, b"no intercept")
                assert response == b"no intercept"
            finally:
                await api.stop()


# ---------------------------------------------------------------------------
# Session limit
# ---------------------------------------------------------------------------

class TestSessionLimit:
    @pytest.mark.asyncio
    async def test_max_sessions_enforced(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                max_sessions=1,
            )
            api = ProtoPokeAPI([config])
            await api.start()

            try:
                # Hold one connection open
                r1, w1 = await asyncio.open_connection("127.0.0.1", listen_port)
                w1.write(b"hold")
                await w1.drain()

                await asyncio.sleep(0.1)

                # Second connection should be rejected
                r2, w2 = await asyncio.open_connection("127.0.0.1", listen_port)
                await asyncio.sleep(0.1)
                # Attempt to read -- should get EOF (rejected)
                data = await asyncio.wait_for(r2.read(1), timeout=1.0)
                assert data == b""

                w1.close()
                w2.close()
            finally:
                await api.stop()


# ---------------------------------------------------------------------------
# Upstream connection failure
# ---------------------------------------------------------------------------

class TestUpstreamFailure:
    @pytest.mark.asyncio
    async def test_closed_upstream_rejects_cleanly(self):
        """If upstream is not running, the client should get a clean close."""
        dead_port = free_port()  # Nothing listening here
        listen_port = free_port()
        config = ForwarderConfig(
            name="Test",
            listen_host="127.0.0.1", listen_port=listen_port,
            upstream_host="127.0.0.1", upstream_port=dead_port,
            connect_timeout=1.0,
        )
        api = ProtoPokeAPI([config])
        await api.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
            data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            assert data == b""  # EOF -- proxy closed the connection
            writer.close()
        finally:
            await api.stop()


# ---------------------------------------------------------------------------
# Shutdown with active session (regression: stop() deadlock)
# ---------------------------------------------------------------------------

class TestShutdownWithActiveSession:
    @pytest.mark.asyncio
    async def test_stop_while_session_active(self):
        """
        stop() must complete even when a client is still connected.

        Regression test for the bug where wait_closed() was called before
        cancelling session tasks, causing a deadlock: the open connections
        were never closed because the tasks that own them were never cancelled.
        """
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()

            # Open a connection but intentionally do NOT close it -- the session
            # stays active while we ask the proxy to stop.
            reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
            writer.write(b"hello")
            await writer.drain()
            await asyncio.sleep(0.05)  # Let the session become ACTIVE

            assert len(api.list_sessions()) == 1

            # stop() must return within a short timeout; if it deadlocks the
            # wait_for will raise asyncio.TimeoutError and fail the test.
            await asyncio.wait_for(api.stop(), timeout=3.0)

            # Clean up the dangling client connection (proxy has already closed
            # its side, so we may get EOF or a connection-reset here).
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Config update after toggle off/on
# ---------------------------------------------------------------------------

class TestForwarderConfigUpdate:
    @pytest.mark.asyncio
    async def test_update_forwarders_applies_new_upstream(self):
        """After stop → update_forwarders with new upstream → start, traffic
        must reach the NEW upstream, not the old one."""
        async with echo_server_ctx() as (host_a, port_a):
            listen_port = free_port()
            fwd = ForwarderConfig(
                name="test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=host_a, upstream_port=port_a,
            )
            api = ProtoPokeAPI([fwd])
            await api.start_forwarder("test")
            try:
                # Verify initial routing
                resp = await send_recv("127.0.0.1", listen_port, b"to-A")
                assert resp == b"to-A"
            finally:
                await api.stop_forwarder("test")

            # Now start a SECOND echo server and re-point the forwarder
            async with echo_server_ctx() as (host_b, port_b):
                new_listen = free_port()
                fwd_updated = ForwarderConfig(
                    name="test",
                    listen_host="127.0.0.1", listen_port=new_listen,
                    upstream_host=host_b, upstream_port=port_b,
                )
                api.update_forwarders([fwd_updated])
                await api.start_forwarder("test")
                try:
                    resp = await send_recv("127.0.0.1", new_listen, b"to-B")
                    assert resp == b"to-B"
                finally:
                    await api.stop_forwarder("test")
