"""Tests for ReplayEngine.send_frame() (Repeater single-frame send)."""

from __future__ import annotations

import asyncio
import socket

import pytest

from protopoke.core.session import SessionRegistry
from protopoke.replay.engine import ReplayEngine
from protopoke.replay.models import SendRecord


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _echo_server_task(host: str, port: int):
    """Simple echo server used in tests."""
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(handler, host, port)
    return server


@pytest.fixture
def engine():
    return ReplayEngine(session_registry=SessionRegistry())


@pytest.mark.asyncio
class TestSendFrame:
    async def test_sends_and_receives(self, engine):
        port = free_port()
        server = await _echo_server_task("127.0.0.1", port)
        async with server:
            rec = await engine.send_frame(b"\x01\x02\x03", "127.0.0.1", port)

        assert rec.success is True
        assert rec.sent_bytes == b"\x01\x02\x03"
        assert rec.received_bytes == b"\x01\x02\x03"
        assert rec.host == "127.0.0.1"
        assert rec.port == port

    async def test_connection_refused(self, engine):
        port = free_port()  # nothing listening there
        rec = await engine.send_frame(b"\x00", "127.0.0.1", port)
        assert rec.success is False
        assert rec.error is not None
        assert rec.received_bytes == b""

    async def test_timeout(self, engine):
        # Connect to a port that drops connections silently by pointing at
        # a port where nothing listens with a very short timeout.
        port = free_port()
        rec = await engine.send_frame(
            b"\x00", "10.255.255.1", port, connect_timeout=0.05
        )
        assert rec.success is False
        assert rec.sent_bytes == b"\x00"

    async def test_returns_send_record(self, engine):
        port = free_port()
        server = await _echo_server_task("127.0.0.1", port)
        async with server:
            rec = await engine.send_frame(b"hello", "127.0.0.1", port)
        assert isinstance(rec, SendRecord)
        assert rec.id  # non-empty UUID

    async def test_empty_bytes(self, engine):
        port = free_port()
        server = await _echo_server_task("127.0.0.1", port)
        async with server:
            rec = await engine.send_frame(b"", "127.0.0.1", port)
        # An empty send: server echoes nothing back
        assert rec.success is True
        assert rec.received_bytes == b""

    async def test_receive_timeout_returns_partial_response(self, engine):
        """Server sends data but never closes — receive_timeout must unblock."""
        port = free_port()

        async def _non_closing_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read(4096)  # drain client bytes
            writer.write(b"\xaa\xbb\xcc")
            await writer.drain()
            await asyncio.sleep(60)  # keep connection open
            writer.close()

        server = await asyncio.start_server(_non_closing_handler, "127.0.0.1", port)
        async with server:
            rec = await engine.send_frame(
                b"\x01\x02\x03",
                "127.0.0.1",
                port,
                receive_timeout=0.5,
            )

        assert rec.success is True
        assert rec.sent_bytes == b"\x01\x02\x03"
        assert rec.received_bytes == b"\xaa\xbb\xcc"

    async def test_receive_timeout_no_response(self, engine):
        """Server accepts but sends nothing — receive_timeout must unblock."""
        port = free_port()

        async def _silent_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read(4096)  # drain client bytes
            await asyncio.sleep(60)  # never respond
            writer.close()

        server = await asyncio.start_server(_silent_handler, "127.0.0.1", port)
        async with server:
            rec = await engine.send_frame(
                b"\xde\xad",
                "127.0.0.1",
                port,
                receive_timeout=0.3,
            )

        assert rec.success is True
        assert rec.sent_bytes == b"\xde\xad"
        assert rec.received_bytes == b""
