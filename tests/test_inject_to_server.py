"""Tests for ProxyEngine.inject_to_server() and ProtoPokeAPI.inject_to_server().

The inject path lets the Forge feature write forged bytes into the upstream TCP
connection of an *existing* proxy session -- the bytes arrive on the same
connection the real client is using, so the server can process them with
full session context.
"""

from __future__ import annotations

import asyncio

import pytest

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig
from tests.conftest import echo_server_ctx, free_port


async def _connect_through_proxy(proxy_host: str, proxy_port: int) -> tuple:
    """Open a connection to the proxy and return (reader, writer)."""
    return await asyncio.open_connection(proxy_host, proxy_port)


@pytest.mark.asyncio
class TestInjectToServer:

    async def test_inject_sends_bytes_to_server(self):
        """Injected bytes arrive at the upstream server on the same TCP connection."""
        received_by_server: list[bytes] = []

        async def recording_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    received_by_server.append(data)
                    writer.write(data)
                    await writer.drain()
            except (ConnectionResetError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        upstream_port = free_port()
        server = await asyncio.start_server(recording_handler, "127.0.0.1", upstream_port)
        async with server:
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host="127.0.0.1", upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                # Establish a proxied connection so a session is created
                client_reader, client_writer = await asyncio.open_connection(
                    "127.0.0.1", listen_port
                )
                client_writer.write(b"hello")
                await client_writer.drain()
                await asyncio.sleep(0.1)  # let the relay set up

                sessions = api.list_active_sessions()
                assert len(sessions) == 1
                session_id = sessions[0].id

                # Inject a forged packet through the existing session
                injected = await api.inject_to_server(session_id, b"forged-packet")
                assert injected is True

                await asyncio.sleep(0.1)
                assert any(b"forged-packet" in chunk for chunk in received_by_server)

                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass
            finally:
                await api.stop()

    async def test_inject_returns_false_for_unknown_session(self):
        """inject_to_server returns False when the session ID doesn't exist."""
        listen_port = free_port()
        async with echo_server_ctx() as (upstream_host, upstream_port):
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                result = await api.inject_to_server("nonexistent-session-id", b"\x01\x02")
                assert result is False
            finally:
                await api.stop()

    async def test_inject_returns_false_after_session_closes(self):
        """inject_to_server returns False once the session's connection closes."""
        async with echo_server_ctx() as (upstream_host, upstream_port):
            listen_port = free_port()
            # Use the legacy disconnect behaviour so closing the client also
            # tears down the upstream session — the new default keeps the
            # server side alive (covered by a dedicated test).
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host=upstream_host, upstream_port=upstream_port,
                keep_upstream_on_client_disconnect=False,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                client_reader, client_writer = await asyncio.open_connection(
                    "127.0.0.1", listen_port
                )
                client_writer.write(b"ping")
                await client_writer.drain()
                await asyncio.sleep(0.1)

                sessions = api.list_active_sessions()
                assert len(sessions) == 1
                session_id = sessions[0].id

                # Close the client connection
                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass
                await asyncio.sleep(0.2)  # let relay tasks finish cleanup

                # The session is now closed -- writer should be gone
                result = await api.inject_to_server(session_id, b"\x01")
                assert result is False
            finally:
                await api.stop()

    async def test_inject_works_after_client_disconnect(self):
        """
        With the default ``keep_upstream_on_client_disconnect=True``, a client
        disconnect must NOT close the upstream connection — Forge can still
        inject into it.
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
            try:
                client_reader, client_writer = await asyncio.open_connection(
                    "127.0.0.1", listen_port
                )
                client_writer.write(b"ping")
                await client_writer.drain()
                await asyncio.sleep(0.1)

                sessions = api.list_active_sessions()
                assert len(sessions) == 1
                session_id = sessions[0].id

                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass
                await asyncio.sleep(0.2)

                # Server connection should still be alive — inject succeeds.
                result = await api.inject_to_server(session_id, b"after-close")
                assert result is True

                # Terminating the session releases the upstream and now
                # inject must return False.
                await api.terminate_session(session_id)
                await asyncio.sleep(0.2)
                result_after = await api.inject_to_server(session_id, b"\x01")
                assert result_after is False
            finally:
                await api.stop()

    async def test_inject_uses_existing_connection_not_new_one(self):
        """
        The upstream server receives injected bytes on the same connection as
        the original client traffic -- there is no second TCP connection created.
        """
        connection_count = 0

        async def counting_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            nonlocal connection_count
            connection_count += 1
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except (ConnectionResetError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        upstream_port = free_port()
        server = await asyncio.start_server(counting_handler, "127.0.0.1", upstream_port)
        async with server:
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host="127.0.0.1", upstream_port=upstream_port,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                client_reader, client_writer = await asyncio.open_connection(
                    "127.0.0.1", listen_port
                )
                await asyncio.sleep(0.1)
                assert connection_count == 1

                sessions = api.list_active_sessions()
                session_id = sessions[0].id

                # Inject several packets -- must NOT open additional connections
                await api.inject_to_server(session_id, b"pkt-1")
                await api.inject_to_server(session_id, b"pkt-2")
                await asyncio.sleep(0.1)

                # Still exactly one upstream connection
                assert connection_count == 1

                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass
            finally:
                await api.stop()
