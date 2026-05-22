"""Tests for ProxyEngine.inject_to_client() and ProtoPokeAPI.inject_to_client().

The inject path lets the Forge feature push forged bytes toward the client of
an *existing* proxy session -- the bytes arrive on the same TCP connection the
real client uses, so the client sees them as if they came from the server.

The key scenario covered here is the symmetric counterpart of
``keep_upstream_on_client_disconnect``: when the upstream server disconnects,
the proxy must not half-close its write side toward the client, so Forge can
keep injecting server→client frames.
"""

from __future__ import annotations

import asyncio

import pytest

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig
from tests.conftest import free_port


@pytest.mark.asyncio
class TestInjectToClient:

    async def test_inject_works_after_server_disconnect(self):
        """
        With the default ``keep_client_on_server_disconnect=True``, an upstream
        server disconnect must NOT close the client-side write channel — Forge
        can still inject toward the client.
        """
        # An upstream server that accepts one connection, reads one chunk, and
        # then closes — simulating ``nc -vlp`` being terminated.
        upstream_port = free_port()
        server_closed = asyncio.Event()

        async def short_lived_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await reader.read(4096)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                server_closed.set()

        server = await asyncio.start_server(
            short_lived_handler, "127.0.0.1", upstream_port
        )
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
                client_writer.write(b"hello")
                await client_writer.drain()
                await asyncio.sleep(0.1)

                sessions = api.list_active_sessions()
                assert len(sessions) == 1
                session_id = sessions[0].id

                # Wait for the upstream server to drop the connection.
                await asyncio.wait_for(server_closed.wait(), timeout=1.0)
                await asyncio.sleep(0.2)

                # Session must still be active (ONLY_CLIENT) and the client
                # writer reachable for injection.
                session = api.get_session(session_id)
                assert session is not None
                assert session.is_active()

                result = await api.inject_to_client(session_id, b"forged-from-forge")
                assert result is True

                # The client should actually receive the injected bytes.
                got = await asyncio.wait_for(client_reader.read(4096), timeout=1.0)
                assert b"forged-from-forge" in got

                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass
            finally:
                await api.stop()

    async def test_legacy_mode_propagates_server_eof_to_client(self):
        """
        With ``keep_client_on_server_disconnect=False`` (legacy), the server's
        EOF is forwarded to the client as a half-close and the session ends.
        """
        upstream_port = free_port()
        server_closed = asyncio.Event()

        async def short_lived_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await reader.read(4096)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                server_closed.set()

        server = await asyncio.start_server(
            short_lived_handler, "127.0.0.1", upstream_port
        )
        async with server:
            listen_port = free_port()
            config = ForwarderConfig(
                name="Test",
                listen_host="127.0.0.1", listen_port=listen_port,
                upstream_host="127.0.0.1", upstream_port=upstream_port,
                keep_client_on_server_disconnect=False,
            )
            api = ProtoPokeAPI([config])
            await api.start()
            try:
                client_reader, client_writer = await asyncio.open_connection(
                    "127.0.0.1", listen_port
                )
                client_writer.write(b"hello")
                await client_writer.drain()
                await asyncio.sleep(0.1)

                await asyncio.wait_for(server_closed.wait(), timeout=1.0)
                # Read until EOF — the proxy should propagate the half-close.
                data = await asyncio.wait_for(client_reader.read(), timeout=1.0)
                assert data == b""

                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass
            finally:
                await api.stop()
