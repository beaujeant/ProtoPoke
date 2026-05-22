"""Unit tests for the SOCKS5 wire protocol parser/encoder."""

from __future__ import annotations

import asyncio
import struct

import pytest

from protopoke.core import socks5


def _make_streams() -> tuple[asyncio.StreamReader, asyncio.StreamWriter, "asyncio.StreamReader", "asyncio.StreamWriter"]:
    """
    Build a connected pair of asyncio Stream{Reader,Writer} backed by an
    in-memory FIFO. Returns (client_reader, client_writer, server_reader, server_writer).

    The client writes feed the server reader and vice versa.
    """
    raise NotImplementedError  # placeholder — see helpers below


class _MemoryReader(asyncio.StreamReader):
    """A StreamReader subclass with simple feed-from-queue semantics."""


def _new_pair() -> tuple[asyncio.StreamReader, "_FakeWriter"]:
    """Return a (reader, writer-like) pair where writer.write feeds the reader."""
    reader = asyncio.StreamReader(limit=1 << 20)

    class _FakeWriter:
        def __init__(self) -> None:
            self._closed = False

        def write(self, data: bytes) -> None:
            reader.feed_data(data)

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            if not self._closed:
                self._closed = True
                reader.feed_eof()

        def get_extra_info(self, _name: str, default=None):
            if _name == "sockname":
                return ("127.0.0.1", 12345)
            return default

    return reader, _FakeWriter()


async def _negotiate_with_client_bytes(
    client_bytes: bytes,
    auth_user=None,
    auth_pass=None,
):
    """
    Drive socks5.negotiate by feeding *client_bytes* as if from a SOCKS5 client.

    Returns ``(parsed_target, server_reply_bytes)``.
    """
    server_in_reader = asyncio.StreamReader(limit=1 << 20)
    server_in_reader.feed_data(client_bytes)
    server_in_reader.feed_eof()

    captured = bytearray()

    class _ReplyWriter:
        def write(self, data: bytes) -> None:
            captured.extend(data)

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            pass

        def get_extra_info(self, _name: str, default=None):
            if _name == "sockname":
                return ("127.0.0.1", 23456)
            return default

    target = await socks5.negotiate(
        server_in_reader,
        _ReplyWriter(),  # type: ignore[arg-type]
        auth_user,
        auth_pass,
    )
    return target, bytes(captured)


# ---------------------------------------------------------------------------
# Greeting + method selection
# ---------------------------------------------------------------------------

async def test_no_auth_ipv4_request_succeeds():
    request = b"".join([
        b"\x05\x01\x00",                 # greeting: 1 method = no-auth
        b"\x05\x01\x00\x01",             # version, CONNECT, RSV, ATYP=IPv4
        bytes([10, 0, 0, 5]),            # 10.0.0.5
        struct.pack("!H", 9999),         # port
    ])
    target, reply = await _negotiate_with_client_bytes(request)
    assert target == ("10.0.0.5", 9999)
    assert reply.startswith(b"\x05\x00")  # method-selection: no-auth


async def test_domain_address_passes_through_unresolved():
    host = b"example.com"
    request = b"".join([
        b"\x05\x01\x00",
        b"\x05\x01\x00\x03",
        bytes([len(host)]) + host,
        struct.pack("!H", 80),
    ])
    target, _ = await _negotiate_with_client_bytes(request)
    assert target == ("example.com", 80)


async def test_ipv6_address_parsed():
    raw = bytes.fromhex("20010db8000000000000000000000001")
    request = b"".join([
        b"\x05\x01\x00",
        b"\x05\x01\x00\x04",
        raw,
        struct.pack("!H", 443),
    ])
    target, _ = await _negotiate_with_client_bytes(request)
    assert target[0] == "2001:db8::1"
    assert target[1] == 443


async def test_method_not_acceptable_when_user_pass_required_but_unoffered():
    request = b"\x05\x01\x00"   # only no-auth offered
    with pytest.raises(socks5.Socks5Error) as exc_info:
        await _negotiate_with_client_bytes(
            request, auth_user="alice", auth_pass="s3cret",
        )
    assert exc_info.value.reply is socks5.Socks5Reply.CONN_NOT_ALLOWED


async def test_userpass_auth_success():
    user = b"alice"
    pwd  = b"s3cret"
    request = b"".join([
        b"\x05\x01\x02",                              # offer user/pass
        b"\x01" + bytes([len(user)]) + user
              + bytes([len(pwd)])  + pwd,             # RFC 1929 auth
        b"\x05\x01\x00\x01\x7f\x00\x00\x01",          # CONNECT 127.0.0.1
        struct.pack("!H", 80),
    ])
    target, reply = await _negotiate_with_client_bytes(
        request, auth_user="alice", auth_pass="s3cret",
    )
    assert target == ("127.0.0.1", 80)
    # method-selection (0x05 0x02) + auth-OK (0x01 0x00) at the start.
    assert reply.startswith(b"\x05\x02\x01\x00")


async def test_userpass_auth_failure():
    request = b"".join([
        b"\x05\x01\x02",
        b"\x01\x05alice\x05bogus",
        b"\x05\x01\x00\x01\x7f\x00\x00\x01",
        struct.pack("!H", 80),
    ])
    with pytest.raises(socks5.Socks5Error) as exc_info:
        await _negotiate_with_client_bytes(
            request, auth_user="alice", auth_pass="s3cret",
        )
    assert exc_info.value.reply is socks5.Socks5Reply.CONN_NOT_ALLOWED


async def test_command_not_supported_for_udp_associate():
    # Offer no-auth so we get past method selection, then send UDP-ASSOCIATE.
    request = b"".join([
        b"\x05\x01\x00",
        b"\x05\x03\x00\x01\x7f\x00\x00\x01",
        struct.pack("!H", 80),
    ])
    with pytest.raises(socks5.Socks5Error) as exc_info:
        await _negotiate_with_client_bytes(request)
    assert exc_info.value.reply is socks5.Socks5Reply.COMMAND_NOT_SUPPORTED


async def test_unsupported_socks_version():
    request = b"\x04\x01\x00"
    with pytest.raises(socks5.Socks5Error):
        await _negotiate_with_client_bytes(request)


async def test_send_reply_ipv4_encoding():
    # Verify the reply payload format end-to-end.
    server_in = asyncio.StreamReader(limit=1 << 20)
    captured = bytearray()

    class _W:
        def write(self, data: bytes) -> None:
            captured.extend(data)
        async def drain(self) -> None: ...
        def close(self) -> None: ...

    await socks5.send_reply(_W(), socks5.Socks5Reply.SUCCEEDED, "192.168.1.1", 1080)  # type: ignore[arg-type]
    expected = b"".join([
        b"\x05\x00\x00\x01",
        bytes([192, 168, 1, 1]),
        struct.pack("!H", 1080),
    ])
    assert bytes(captured) == expected
