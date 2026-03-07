"""
Shared pytest fixtures for tcpproxy tests.

Provides:
    echo_server(host, port) — async context manager that starts/stops a TCP echo server
    free_port()             — returns an available local TCP port
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import pytest


def free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@asynccontextmanager
async def echo_server_ctx(host: str = "127.0.0.1", port: int = 0):
    """
    Async context manager: starts a TCP echo server, yields (host, port), stops on exit.

    Usage:
        async with echo_server_ctx() as (host, port):
            reader, writer = await asyncio.open_connection(host, port)
            ...
    """
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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

    server = await asyncio.start_server(handler, host, port)
    bound_port = server.sockets[0].getsockname()[1]
    try:
        yield host, bound_port
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
def unused_port():
    """Pytest fixture: returns an available local TCP port."""
    return free_port()
