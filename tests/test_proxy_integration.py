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

from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
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
    async def test_event_bus_frame_events(self):
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProxyAPI(config)
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                intercept_enabled=True,
            )
            api = ProxyAPI(config)
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                intercept_enabled=True,
            )
            api = ProxyAPI(config)
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                intercept_enabled=True,
            )
            api = ProxyAPI(config)
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
                # Drop the client→server frame; server should not echo anything
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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                intercept_enabled=True,
            )
            api = ProxyAPI(config)
            await api.start()

            # Disable interception — everything should flow through
            api.intercept_enabled = False

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
            config = ProxyConfig(
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                max_sessions=1,
            )
            api = ProxyAPI(config)
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
                # Attempt to read — should get EOF (rejected)
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
        config = ProxyConfig(
            listen_host="127.0.0.1", listen_port=listen_port,
            upstream_host="127.0.0.1", upstream_port=dead_port,
            connect_timeout=1.0,
        )
        api = ProxyAPI(config)
        await api.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
            data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            assert data == b""  # EOF — proxy closed the connection
            writer.close()
        finally:
            await api.stop()
