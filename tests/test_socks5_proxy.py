"""End-to-end SOCKS5 proxy tests."""

from __future__ import annotations

import asyncio
import struct

import pytest

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig, ForwarderType
from protopoke.models import Direction, SessionState

from .conftest import echo_server_ctx, free_port


async def _socks5_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    auth: tuple[str, str] | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Drive a SOCKS5 client by hand and return the proxied (reader, writer)."""
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

    # Greeting
    if auth:
        writer.write(b"\x05\x01\x02")
    else:
        writer.write(b"\x05\x01\x00")
    await writer.drain()

    method_reply = await reader.readexactly(2)
    assert method_reply[0] == 0x05

    # User/pass sub-negotiation if requested
    if auth:
        assert method_reply[1] == 0x02
        user, pwd = auth
        u = user.encode("utf-8")
        p = pwd.encode("utf-8")
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        auth_reply = await reader.readexactly(2)
        if auth_reply[1] != 0x00:
            raise RuntimeError("SOCKS5 auth rejected")
    else:
        assert method_reply[1] == 0x00

    # Send CONNECT
    host_bytes = target_host.encode("ascii")
    request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", target_port)
    writer.write(request)
    await writer.drain()

    # Reply
    head = await reader.readexactly(4)
    assert head[0] == 0x05
    if head[1] != 0x00:
        raise RuntimeError(f"SOCKS5 CONNECT failed: {head[1]:#04x}")
    atyp = head[3]
    if atyp == 0x01:
        await reader.readexactly(4)
    elif atyp == 0x04:
        await reader.readexactly(16)
    elif atyp == 0x03:
        ln = (await reader.readexactly(1))[0]
        await reader.readexactly(ln)
    await reader.readexactly(2)  # bnd port

    return reader, writer


async def test_socks5_no_auth_relays_traffic():
    proxy_port = free_port()

    async with echo_server_ctx() as (echo_host, echo_port):
        config = ForwarderConfig(
            name="socks-test",
            forwarder_type=ForwarderType.SOCKS5,
            listen_host="127.0.0.1",
            listen_port=proxy_port,
        )
        api = ProtoPokeAPI(forwarders=[config])
        await api.start()
        try:
            await asyncio.sleep(0.05)

            reader, writer = await _socks5_connect(
                "127.0.0.1", proxy_port, echo_host, echo_port,
            )
            try:
                writer.write(b"hello world")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(11), timeout=2.0)
                assert resp == b"hello world"
            finally:
                writer.close()

            # Allow the relay to flush the close.
            await asyncio.sleep(0.1)

            sessions = api.list_sessions()
            assert len(sessions) == 1
            info = sessions[0].info
            assert info.transport == "socks5"
            assert info.server_host == echo_host
            assert info.server_port == echo_port
        finally:
            await api.stop()


async def test_socks5_userpass_auth_success():
    proxy_port = free_port()

    async with echo_server_ctx() as (echo_host, echo_port):
        config = ForwarderConfig(
            name="socks-auth",
            forwarder_type=ForwarderType.SOCKS5,
            listen_host="127.0.0.1",
            listen_port=proxy_port,
            socks_auth_username="alice",
            socks_auth_password="s3cret",
        )
        api = ProtoPokeAPI(forwarders=[config])
        await api.start()
        try:
            await asyncio.sleep(0.05)

            reader, writer = await _socks5_connect(
                "127.0.0.1", proxy_port, echo_host, echo_port,
                auth=("alice", "s3cret"),
            )
            try:
                writer.write(b"AUTH OK")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(7), timeout=2.0)
                assert resp == b"AUTH OK"
            finally:
                writer.close()
        finally:
            await api.stop()


async def test_socks5_userpass_auth_failure():
    proxy_port = free_port()

    async with echo_server_ctx() as (echo_host, echo_port):
        config = ForwarderConfig(
            name="socks-auth-bad",
            forwarder_type=ForwarderType.SOCKS5,
            listen_host="127.0.0.1",
            listen_port=proxy_port,
            socks_auth_username="alice",
            socks_auth_password="s3cret",
        )
        api = ProtoPokeAPI(forwarders=[config])
        await api.start()
        try:
            await asyncio.sleep(0.05)
            with pytest.raises(RuntimeError, match="SOCKS5 auth rejected"):
                await _socks5_connect(
                    "127.0.0.1", proxy_port, echo_host, echo_port,
                    auth=("alice", "wrong"),
                )
        finally:
            await api.stop()


def test_socks5_with_tls_listen_is_rejected_at_config_time():
    with pytest.raises(ValueError, match="SOCKS5"):
        ForwarderConfig(
            name="bad",
            forwarder_type=ForwarderType.SOCKS5,
            listen_host="127.0.0.1",
            listen_port=12345,
            tls_listen=True,
        )
